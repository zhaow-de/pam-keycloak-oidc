package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// number of integers in the OTP. Google Authenticator expects this to be 6 digits
const digits int = 6

// interval in seconds between two OTP tokens. Google Authenticator expects this to be 30 seconds
const interval int64 = 30

// loadConfig loads configuration from the default location.
// Maintained for backward compatibility - calls log.Fatal on error.
func loadConfig() *Config {
	config, err := loadConfigWithError()
	if err != nil {
		log.Fatal("Unable to load config file. Error: ", err)
	}
	return config
}

func genUsername(username, secret string, xorKey string) (output string) {
	usernamePart := []byte(username + ":")
	secretPart := b32decode(secret)
	if len(secretPart) == 0 {
		panic("\"" + secret + "\" does not look like an OTP secret")
	}
	return a85Encode(encryptDecrypt(append(usernamePart, secretPart...), xorKey))
}

func decodeUsername(encodedUsername string, xorKey string) (username, secret string) {
	input := encryptDecrypt(a85Decode(encodedUsername), xorKey)
	var decodedSecret []byte

	var rxUsername = regexp.MustCompile("^[a-zA-Z0-9_.-]+$")

	for r := 0; r < len(input); r++ {
		c := input[r]
		if c == ':' {
			username = string(input[0:r])
			decodedSecret = input[r+1:]
			break
		}
	}
	if username == "" || len(decodedSecret) == 0 || !rxUsername.MatchString(username) {
		return "", ""
	}
	secret = b32encode(decodedSecret)
	return username, secret
}

func calculateOtpToken(secret string, timestamp int64) string {
	if len(secret) <= 0 || timestamp < 0 {
		return ""
	}
	input := timestamp / interval
	//
	// add the missing padding if needed, then decode the secret
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secret = secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return ""
	}
	// start hashing
	sha1Hash := hmac.New(sha1.New, bytes)
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(input & 0xff)
		input = input >> 8
	}
	sha1Hash.Write(byteArr)
	hmacHash := sha1Hash.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := (((int(hmacHash[offset]) & 0x7f) << 24) | ((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) | (int(hmacHash[offset+3]) & 0xff)) % int(math.Pow10(digits))

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}

func main() {
	config := loadConfig()
	//
	// check the number of arguments to determine the scenario:
	//   two arguments: generate the secret username
	//   one argument: validate the secret username
	//   no argument: PAM auth
	if len(os.Args) == 3 {
		fmt.Println("Your secret username: " + genUsername(os.Args[1], os.Args[2], config.XORKey))
		return
	} else if len(os.Args) == 2 {
		fmt.Println("Please double check carefully the secret username you entered is: " + os.Args[1])
		username, secret := decodeUsername(os.Args[1], config.XORKey)
		fmt.Println("Your real username: '" + username + "'. Your TOTP secret: '" + secret +
			"'. Your TOTP token for now is: '" + calculateOtpToken(secret, time.Now().Unix()) + "'.")
		return
	}
	//
	// Only the authentication path needs a complete config; the two username
	// utilities above run on a half-configured box on purpose.
	if err := config.Validate(); err != nil {
		log.Fatal("Configuration is incomplete: ", err)
	}
	var inputEnv, inputStdio string
	//
	// Extract username, password, and otpCode
	var username, password, otpCode string
	inputEnv = os.Getenv("PAM_USER")
	stdinScanner := bufio.NewScanner(os.Stdin)
	if stdinScanner.Scan() {
		inputStdio = strings.Trim(stdinScanner.Text(), "\x00")
	}
	var otpSecret string
	username, otpSecret = decodeUsername(inputEnv, config.XORKey)
	if username != "" && otpSecret != "" {
		// advanced user detected, who knows how to combine the real username and the OTP secret into the VPN username
		otpCode = calculateOtpToken(otpSecret, time.Now().Unix())
		password = inputStdio
	} else {
		// regular user detected, whose OTP is the tail of what they typed.
		username = inputEnv
		//
		// otp-class is a complete regex atom, not a bare escape letter: `\d` and
		// `[a-zA-Z0-9]` are both valid. Compile, never MustCompile — a bad class
		// in a config file must not panic the auth path.
		passwordPattern, err := regexp.Compile(`^(.+)(` + config.OTPClass + `{` + config.OTPLength + `})$`)
		if err != nil {
			log.Fatal("Invalid otp-class/otp-length: ", err)
		}
		match := passwordPattern.FindStringSubmatch(inputStdio)
		if match != nil {
			password = match[1]
			otpCode = match[2]
		} else if config.OTPOnly {
			password = "_"
			otpCode = inputStdio
		} else if config.OTPRequire {
			// Refuse rather than silently attempting a password-only bind.
			password = inputStdio
			otpCode = ""
			log.Println("Rejected: otp-require is set and no OTP was appended to the password")
			os.Exit(11)
		} else {
			password = inputStdio
			otpCode = ""
		}
	}
	sid := fmt.Sprintf("[%s]-(%s) ", uuid.New().String(), username)
	if username == "" || password == "" {
		log.Println(sid, "Unable to get all the parts for authentication.", "Username: \""+inputEnv+"\"")
		os.Exit(11) // PAM_CRED_INSUFFICIENT
	}
	//
	// Authenticate
	//
	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthEndpoint,
			TokenURL: config.TokenEndpoint,
		},
	}
	extraParameters := url.Values{}
	for k, v := range config.ExtraParameters {
		extraParameters[k] = []string{v}
	}

	oauth2Context := context.Background()

	accessToken, err := passwordCredentialsTokenEx(
		oauth2Context,
		oauth2Config,
		fmt.Sprintf(config.UsernameFormat, username),
		password,
		otpCode,
		config.Scope,
		extraParameters,
	)
	if err != nil {
		log.Print(sid, strings.ReplaceAll(err.Error(), "\n", ". "))
		os.Exit(2)
	}

	//
	// Verify the access token against the keys the IdP publishes. Until this landed,
	// jwt.Parse's error was discarded and token.Valid was never read, so ANY signature
	// was accepted; the alg header was the only thing inspected.
	jwksBody, err := fetchJWKS(config.JwksUrl, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		log.Print(sid, "JWKS unavailable: ", strings.ReplaceAll(err.Error(), "\n", ". "))
		os.Exit(4)
	}
	signingKeys, err := parseJWKS(jwksBody)
	if err != nil {
		log.Print(sid, "JWKS unusable: ", strings.ReplaceAll(err.Error(), "\n", ". "))
		os.Exit(4)
	}

	parserOptions := []jwt.ParserOption{jwt.WithExpirationRequired()}
	if config.IssuerUrl != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(config.IssuerUrl))
	}
	//
	// Opt-in: a stock Keycloak access token carries aud:["account"], not the client id,
	// unless an Audience mapper is configured — verifying it by default would lock every
	// existing deployment out on upgrade.
	if config.VerifyAudience {
		parserOptions = append(parserOptions, jwt.WithAudience(config.ClientId))
	}

	token, err := jwt.Parse(accessToken, newJWKSKeyfunc(signingKeys), parserOptions...)
	if err != nil {
		log.Print(sid, "Access token failed verification: ", strings.ReplaceAll(err.Error(), "\n", ". "))
		os.Exit(2)
	}
	if !token.Valid {
		log.Print(sid, "Access token is not valid")
		os.Exit(2)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Print(sid, "Access token claims are not a JSON object")
		os.Exit(2)
	}
	if checkRoleAuthorization(claims, config.Scope, config.MandatoryUserRole, config.RoleMatch) {
		log.Print(sid, "Authentication succeeded")
		os.Exit(0)
	}

	os.Exit(7) // PAM_PERM_DENIED
}

// checkRoleAuthorization reports whether the token's role claim satisfies the
// configured requirement: "all" needs every listed role, anything else needs one.
//
// The claim is asserted with a checked type assertion on purpose. An IdP that
// publishes the claim as anything but an array of strings used to panic here, and
// a Go panic exits 2 — indistinguishable from an OAuth2 failure.
func checkRoleAuthorization(claims jwt.MapClaims, scope string, required []string, matchMode string) bool {
	if len(required) == 0 {
		return false
	}
	rolesRaw, present := claims[scope]
	if !present {
		return false
	}
	rolesList, isArray := rolesRaw.([]interface{})
	if !isArray {
		return false
	}
	held := make(map[string]bool, len(rolesList))
	for _, item := range rolesList {
		if role, isString := item.(string); isString {
			held[role] = true
		}
	}
	if matchMode == "all" {
		for _, r := range required {
			if !held[r] {
				return false
			}
		}
		return true
	}
	for _, r := range required {
		if held[r] {
			return true
		}
	}
	return false
}
