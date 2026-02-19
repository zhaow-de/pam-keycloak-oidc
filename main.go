package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
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
// Maintained for backward compatibility
func loadConfig() *Config {
	config, err := loadConfigWithError()
	if err != nil {
		log.Print("Unable to load config file. Error: ", err)
		os.Exit(4) // PAM_SYSTEM_ERR
	}
	return config
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

	// Apply OTP defaults and validate configuration
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		log.Print("Configuration error: ", err)
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
		// regular user detected, who should have the OTP code as the last N characters of the password
		username = inputEnv

		// Build OTP extraction pattern from config (default: `\d{6}`)
		passwordPattern, err := regexp.Compile(`^(.+)(` + config.OTPClass + `{` + config.OTPLength + `})$`)
		if err != nil {
			log.Print("Invalid OTP pattern configuration (otp-class/otp-length): ", err)
			os.Exit(4) // PAM_SYSTEM_ERR
		}

		match := passwordPattern.FindStringSubmatch(inputStdio)
		if match != nil {
			password = match[1]
			otpCode = match[2]
		} else {
			if config.OTPOnly {
				password = "_"
				otpCode = inputStdio
			} else if config.OTPRequire {
				log.Print("OTP is required but input does not contain a valid OTP suffix")
				os.Exit(7) // PAM_PERM_DENIED
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
			return nil, fmt.Errorf("algorithm mismatch: token has %s, config expects %s", alg, config.AccessTokenSigningMethod)
		}
		switch {
		case strings.HasPrefix(alg, "RS"):
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", alg)
			}
		case strings.HasPrefix(alg, "ES"):
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", alg)
			}
		case strings.HasPrefix(alg, "EdDSA"):
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", alg)
			}
		default:
			return nil, fmt.Errorf("unsupported signing method: %s", alg)
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
