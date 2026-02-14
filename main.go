package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/ascii85"
	"encoding/base32"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// number of integers in the OTP. Google Authenticator expects this to be 6 digits
const digits int = 6

// interval in seconds between two OTP tokens. Google Authenticator expects this to be 30 seconds
const interval int64 = 30

type Config struct {
	ClientId                 string            `toml:"client-id"`
	ClientSecret             string            `toml:"client-secret"`
	RedirectUri              string            `toml:"redirect-url"`
	Scope                    string            `toml:"scope"`
	AuthEndpoint             string            `toml:"endpoint-auth-url"`
	TokenEndpoint            string            `toml:"endpoint-token-url"`
	UsernameFormat           string            `toml:"username-format"`
	MandatoryUserRole        string            `toml:"vpn-user-role"`
	AccessTokenSigningMethod string            `toml:"access-token-signing-method"`
	XORKey                   string            `toml:"xor-key"`
	OTPOnly                  bool              `toml:"otp-only"`
	JwksUrl                  string            `toml:"jwks-url"`
	IssuerUrl                string            `toml:"issuer-url"`
	ExtraParameters          map[string]string `toml:"extra-parameters"`
}

// load config file
func loadConfig() *Config {
	var configFile string
	if exeName, err := os.Executable(); err != nil {
		log.Print("Unable to get current executable name. Error: ", err)
		os.Exit(4) // PAM_SYSTEM_ERR
	} else {
		configFile = filepath.Clean(exeName + ".tml")
	}
	if _, err := os.Stat(configFile); err != nil {
		log.Print(err)
		os.Exit(4) // PAM_SYSTEM_ERR
	}
	var config Config
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		log.Print("Unable to load config file. Error: ", err)
		os.Exit(4) // PAM_SYSTEM_ERR
	}
	return &config
}

// fetchJWKS retrieves the JSON Web Key Set from the Keycloak JWKS endpoint.
// Returns a keyfunc compatible with jwt.Parse for signature verification.
// Since the PAM module is a short-lived process (spawned per auth attempt),
// we do a single HTTP GET instead of background refresh.
func fetchJWKS(jwksURL string) (jwt.Keyfunc, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("jwks-url is not configured")
	}
	if !strings.HasPrefix(jwksURL, "https://") {
		return nil, fmt.Errorf("jwks-url must use HTTPS")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	k, err := keyfunc.NewJWKSetJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return k.Keyfunc, nil
}

// encryptDecrypt runs XOR encryption on the input string, encrypting it if it hasn't already been,
// and decrypting it if it has, using the key provided.
func encryptDecrypt(input []byte, key string) (output []byte) {
	kL := len(key)
	for i := range input {
		output = append(output, input[i]^key[i%kL])
	}
	return output
}

func a85Encode(input []byte) (output string) {
	result := make([]byte, ascii85.MaxEncodedLen(len(input)))
	n := ascii85.Encode(result, input)
	result = result[0:n]
	output = string(result)
	return output
}

func a85Decode(input string) (output []byte) {
	dBuf := make([]byte, 4*len(input))
	if dLen, _, err := ascii85.Decode(dBuf, []byte(input), true); err == nil {
		return dBuf[0:dLen]
	}
	return nil
}

func b32decode(input string) (output []byte) {
	b32decoded, _ := base32.StdEncoding.DecodeString(strings.ToUpper(input))
	return b32decoded
}

func b32encode(input []byte) (output string) {
	return base32.StdEncoding.EncodeToString(input)
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

// Build-time variables set via -ldflags
var Version = "dev"
var Build = "unknown"

func main() {
	// Handle CLI flags (before PAM auth flow)
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "-v":
			fmt.Printf("pam-keycloak-oidc %s (build %s)\n", Version, Build)
			return
		case "--help", "-h":
			fmt.Println("pam-keycloak-oidc — PAM module for Keycloak OIDC authentication")
			fmt.Printf("Version: %s (build %s)\n\n", Version, Build)
			fmt.Println("Usage:")
			fmt.Println("  pam-keycloak-oidc                        PAM authentication mode (reads PAM_USER env + password from stdin)")
			fmt.Println("  pam-keycloak-oidc <username> <secret>    Generate encoded username from real username and TOTP secret")
			fmt.Println("  pam-keycloak-oidc <encoded-username>     Decode and verify encoded username")
			fmt.Println("  pam-keycloak-oidc --version              Show version")
			fmt.Println("  pam-keycloak-oidc --help                 Show this help")
			fmt.Printf("\nConfig file: <binary-path>.tml ('%s.tml')\n", os.Args[0])
			return
		}
	}

	config := loadConfig()

	if config.IssuerUrl == "" {
		log.Print("issuer-url is not configured")
		os.Exit(4) // PAM_SYSTEM_ERR
	}
	if config.JwksUrl == "" {
		log.Print("jwks-url is not configured")
		os.Exit(4) // PAM_SYSTEM_ERR
	}

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
		// regular user detected, who should have the OTP code as the last 6 digits of the password
		username = inputEnv
		var passwordPattern = regexp.MustCompile(`^(.+)(\d{6})$`)
		match := passwordPattern.FindStringSubmatch(inputStdio)
		if match != nil {
			password = match[1]
			otpCode = match[2]
		} else {
			if config.OTPOnly {
				password = "_"
				otpCode = inputStdio
			} else {
				password = inputStdio
				otpCode = ""
			}
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

	// Fetch JWKS and verify JWT signature
	jwksKeyfunc, err := fetchJWKS(config.JwksUrl)
	if err != nil {
		log.Print(sid, "Failed to fetch JWKS: ", err)
		os.Exit(4) // PAM_SYSTEM_ERR
	}

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing algorithm to prevent algorithm confusion attacks
		// Reference: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
		alg, _ := token.Header["alg"].(string)
		if config.AccessTokenSigningMethod != "" && alg != config.AccessTokenSigningMethod {
			return nil, fmt.Errorf("Algorithm mismatch: token has %s, config expects %s", alg, config.AccessTokenSigningMethod)
		}
		switch {
		case strings.HasPrefix(alg, "RS"):
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %s", alg)
			}
		case strings.HasPrefix(alg, "ES"):
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %s", alg)
			}
		case strings.HasPrefix(alg, "EdDSA"):
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %s", alg)
			}
		default:
			return nil, fmt.Errorf("Unsupported signing method: %s", alg)
		}
		// Delegate to JWKS keyfunc to return the correct public key
		return jwksKeyfunc(token)
	},
		jwt.WithIssuer(config.IssuerUrl),  // reject tokens from other realms
		jwt.WithAudience(config.ClientId), // reject tokens issued for other clients
		jwt.WithExpirationRequired(),      // reject tokens without "exp" claim
	)

	if err != nil {
		log.Print(sid, "JWT verification failed: ", err)
		os.Exit(7)
	}
	if !token.Valid {
		log.Print(sid, "JWT token is not valid")
		os.Exit(7)
	}

	// Token signature verified -- check role claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if roles, ok := claims[config.Scope]; ok {
			for _, item := range roles.([]interface{}) {
				if reflect.ValueOf(item).Kind() == reflect.String && item == config.MandatoryUserRole {
					log.Print(sid, "Authentication succeeded")
					os.Exit(0)
				}
			}
		}
	}

	log.Print(sid, "Authentication was successful but authorization failed")
	os.Exit(7) // PAM_PERM_DENIED
}
