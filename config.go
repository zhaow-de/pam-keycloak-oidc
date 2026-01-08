package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds the OIDC/OAuth2 configuration loaded from a TOML file.
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
	ExtraParameters          map[string]string `toml:"extra-parameters"`
}

// ConfigError represents configuration-related errors with context.
type ConfigError struct {
	Op   string // Operation that failed (e.g., "get_executable", "stat", "decode")
	Path string // File path involved (if applicable)
	Err  error  // Underlying error
}

func (e *ConfigError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("config %s %s: %v", e.Op, e.Path, e.Err)
	}
	return fmt.Sprintf("config %s: %v", e.Op, e.Err)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// ErrMissingRequired is returned when required configuration fields are empty.
var ErrMissingRequired = errors.New("missing required configuration field")

// LoadConfigFromFile loads and parses configuration from the specified TOML file.
func LoadConfigFromFile(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); err != nil {
		return nil, &ConfigError{Op: "stat", Path: configPath, Err: err}
	}

	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, &ConfigError{Op: "decode", Path: configPath, Err: err}
	}

	return &config, nil
}

// LoadConfigFromReader loads configuration from a TOML-formatted string.
// Useful for testing without needing actual files.
func LoadConfigFromReader(tomlContent string) (*Config, error) {
	var config Config
	if _, err := toml.Decode(tomlContent, &config); err != nil {
		return nil, &ConfigError{Op: "decode", Err: err}
	}
	return &config, nil
}

// getDefaultConfigPath returns the default configuration file path
// based on the current executable name.
func getDefaultConfigPath() (string, error) {
	exeName, err := os.Executable()
	if err != nil {
		return "", &ConfigError{Op: "get_executable", Err: err}
	}
	return filepath.Clean(exeName + ".tml"), nil
}

// loadConfigWithError loads configuration from the default location.
// Returns an error instead of calling log.Fatal, making it testable.
func loadConfigWithError() (*Config, error) {
	configPath, err := getDefaultConfigPath()
	if err != nil {
		return nil, err
	}
	return LoadConfigFromFile(configPath)
}

// Validate checks that all required configuration fields are set.
// Returns nil if valid, or an error describing the first missing field.
func (c *Config) Validate() error {
	if c.ClientId == "" {
		return fmt.Errorf("%w: client-id", ErrMissingRequired)
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("%w: client-secret", ErrMissingRequired)
	}
	if c.TokenEndpoint == "" {
		return fmt.Errorf("%w: endpoint-token-url", ErrMissingRequired)
	}
	if c.XORKey == "" {
		return fmt.Errorf("%w: xor-key", ErrMissingRequired)
	}
	return nil
}