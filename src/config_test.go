package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const validConfigTOML = `
client-id="test-client"
client-secret="test-secret"
redirect-url="urn:ietf:wg:oauth:2.0:oob"
scope="test_roles"
vpn-user-role="test-vpn-access"
endpoint-auth-url="https://auth.example.com/auth"
endpoint-token-url="https://auth.example.com/token"
username-format="%s"
access-token-signing-method="RS256"
xor-key="testkey"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"
`

const minimalConfigTOML = `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://auth.example.com/token"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"
`

const configWithExtraParams = `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://auth.example.com/token"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"

[extra-parameters]
grant_type = "custom_grant"
custom_param = "custom_value"
`

const otpOnlyConfigTOML = `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://auth.example.com/token"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"
otp-only=true
`

const otpRequireConfigTOML = `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://auth.example.com/token"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"
otp-require=true
otp-length="8"
otp-class="[a-zA-Z0-9]"
`

const otpDefaultsConfigTOML = `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://auth.example.com/token"
jwks-url="https://auth.example.com/certs"
issuer-url="https://auth.example.com/realms/test"
otp-require=true
`

func TestLoadConfigFromReader_ValidConfig(t *testing.T) {
	config, err := LoadConfigFromReader(validConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if config.ClientId != "test-client" {
		t.Errorf("ClientId = %s; want test-client", config.ClientId)
	}
	if config.ClientSecret != "test-secret" {
		t.Errorf("ClientSecret = %s; want test-secret", config.ClientSecret)
	}
	if config.RedirectUri != "urn:ietf:wg:oauth:2.0:oob" {
		t.Errorf("RedirectUri = %s; want urn:ietf:wg:oauth:2.0:oob", config.RedirectUri)
	}
	if config.Scope != "test_roles" {
		t.Errorf("Scope = %s; want test_roles", config.Scope)
	}
	if config.MandatoryUserRole != "test-vpn-access" {
		t.Errorf("MandatoryUserRole = %s; want test-vpn-access", config.MandatoryUserRole)
	}
	if config.AuthEndpoint != "https://auth.example.com/auth" {
		t.Errorf("AuthEndpoint = %s; want https://auth.example.com/auth", config.AuthEndpoint)
	}
	if config.TokenEndpoint != "https://auth.example.com/token" {
		t.Errorf("TokenEndpoint = %s; want https://auth.example.com/token", config.TokenEndpoint)
	}
	if config.UsernameFormat != "%s" {
		t.Errorf("UsernameFormat = %s; want %%s", config.UsernameFormat)
	}
	if config.AccessTokenSigningMethod != "RS256" {
		t.Errorf("AccessTokenSigningMethod = %s; want RS256", config.AccessTokenSigningMethod)
	}
	if config.XORKey != "testkey" {
		t.Errorf("XORKey = %s; want testkey", config.XORKey)
	}
	if config.JwksUrl != "https://auth.example.com/certs" {
		t.Errorf("JwksUrl = %s; want https://auth.example.com/certs", config.JwksUrl)
	}
	if config.IssuerUrl != "https://auth.example.com/realms/test" {
		t.Errorf("IssuerUrl = %s; want https://auth.example.com/realms/test", config.IssuerUrl)
	}
}

func TestLoadConfigFromReader_MinimalConfig(t *testing.T) {
	config, err := LoadConfigFromReader(minimalConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if config.ClientId != "test-client" {
		t.Errorf("ClientId = %s; want test-client", config.ClientId)
	}
	if config.Scope != "" {
		t.Errorf("Scope = %s; want empty string", config.Scope)
	}
	if config.OTPOnly != false {
		t.Errorf("OTPOnly = %v; want false", config.OTPOnly)
	}
	if config.ExtraParameters != nil {
		t.Errorf("ExtraParameters = %v; want nil", config.ExtraParameters)
	}
}

func TestLoadConfigFromReader_ExtraParameters(t *testing.T) {
	config, err := LoadConfigFromReader(configWithExtraParams)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if config.ExtraParameters == nil {
		t.Fatal("ExtraParameters is nil; want map")
	}
	if len(config.ExtraParameters) != 2 {
		t.Errorf("len(ExtraParameters) = %d; want 2", len(config.ExtraParameters))
	}
	if config.ExtraParameters["grant_type"] != "custom_grant" {
		t.Errorf("ExtraParameters[grant_type] = %s; want custom_grant", config.ExtraParameters["grant_type"])
	}
	if config.ExtraParameters["custom_param"] != "custom_value" {
		t.Errorf("ExtraParameters[custom_param] = %s; want custom_value", config.ExtraParameters["custom_param"])
	}
}

func TestLoadConfigFromReader_OTPOnly(t *testing.T) {
	config, err := LoadConfigFromReader(otpOnlyConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if !config.OTPOnly {
		t.Errorf("OTPOnly = %v; want true", config.OTPOnly)
	}
}

func TestLoadConfigFromReader_OTPRequire(t *testing.T) {
	config, err := LoadConfigFromReader(otpRequireConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if !config.OTPRequire {
		t.Errorf("OTPRequire = %v; want true", config.OTPRequire)
	}
	if config.OTPLength != "8" {
		t.Errorf("OTPLength = %s; want 8", config.OTPLength)
	}
	if config.OTPClass != "[a-zA-Z0-9]" {
		t.Errorf("OTPClass = %s; want [a-zA-Z0-9]", config.OTPClass)
	}
}

func TestLoadConfigFromReader_OTPDefaults(t *testing.T) {
	config, err := LoadConfigFromReader(otpDefaultsConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if !config.OTPRequire {
		t.Errorf("OTPRequire = %v; want true", config.OTPRequire)
	}
	// Before ApplyDefaults, fields should be empty
	if config.OTPLength != "" {
		t.Errorf("OTPLength before ApplyDefaults = %s; want empty", config.OTPLength)
	}
	if config.OTPClass != "" {
		t.Errorf("OTPClass before ApplyDefaults = %s; want empty", config.OTPClass)
	}

	config.ApplyDefaults()

	if config.OTPLength != "6" {
		t.Errorf("OTPLength after ApplyDefaults = %s; want 6", config.OTPLength)
	}
	if config.OTPClass != `\d` {
		t.Errorf("OTPClass after ApplyDefaults = %s; want \\d", config.OTPClass)
	}
}

func TestLoadConfigFromReader_JwksAndIssuer(t *testing.T) {
	config, err := LoadConfigFromReader(validConfigTOML)
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error: %v", err)
	}

	if config.JwksUrl != "https://auth.example.com/certs" {
		t.Errorf("JwksUrl = %s; want https://auth.example.com/certs", config.JwksUrl)
	}
	if config.IssuerUrl != "https://auth.example.com/realms/test" {
		t.Errorf("IssuerUrl = %s; want https://auth.example.com/realms/test", config.IssuerUrl)
	}
}

func TestLoadConfigFromReader_InvalidTOML(t *testing.T) {
	invalidTOML := `client-id="unclosed string`

	_, err := LoadConfigFromReader(invalidTOML)
	if err == nil {
		t.Fatal("LoadConfigFromReader should return error for invalid TOML")
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("error should be *ConfigError, got %T", err)
	}
	if configErr.Op != "decode" {
		t.Errorf("ConfigError.Op = %s; want decode", configErr.Op)
	}
}

func TestLoadConfigFromReader_EmptyInput(t *testing.T) {
	config, err := LoadConfigFromReader("")
	if err != nil {
		t.Fatalf("LoadConfigFromReader returned unexpected error for empty input: %v", err)
	}

	if config.ClientId != "" {
		t.Errorf("ClientId = %s; want empty string", config.ClientId)
	}
}

func TestLoadConfigFromFile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.tml")

	if err := os.WriteFile(configPath, []byte(validConfigTOML), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	config, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile returned unexpected error: %v", err)
	}

	if config.ClientId != "test-client" {
		t.Errorf("ClientId = %s; want test-client", config.ClientId)
	}
}

func TestLoadConfigFromFile_FileNotFound(t *testing.T) {
	_, err := LoadConfigFromFile("/nonexistent/path/config.tml")
	if err == nil {
		t.Fatal("LoadConfigFromFile should return error for nonexistent file")
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("error should be *ConfigError, got %T", err)
	}
	if configErr.Op != "stat" {
		t.Errorf("ConfigError.Op = %s; want stat", configErr.Op)
	}
	if !os.IsNotExist(configErr.Err) {
		t.Errorf("underlying error should be os.IsNotExist")
	}
}

func TestLoadConfigFromFile_InvalidTOML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.tml")

	invalidContent := `client-id="unclosed string`
	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err := LoadConfigFromFile(configPath)
	if err == nil {
		t.Fatal("LoadConfigFromFile should return error for invalid TOML")
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("error should be *ConfigError, got %T", err)
	}
	if configErr.Op != "decode" {
		t.Errorf("ConfigError.Op = %s; want decode", configErr.Op)
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	config, _ := LoadConfigFromReader(minimalConfigTOML)

	if err := config.Validate(); err != nil {
		t.Errorf("Validate returned unexpected error: %v", err)
	}
}

func TestConfig_Validate_MissingClientId(t *testing.T) {
	config := &Config{
		ClientSecret:  "secret",
		TokenEndpoint: "https://example.com/token",
		JwksUrl:       "https://example.com/certs",
		IssuerUrl:     "https://example.com/realms/test",
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing ClientId")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired")
	}
}

func TestConfig_Validate_MissingClientSecret(t *testing.T) {
	config := &Config{
		ClientId:      "client",
		TokenEndpoint: "https://example.com/token",
		JwksUrl:       "https://example.com/certs",
		IssuerUrl:     "https://example.com/realms/test",
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing ClientSecret")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired")
	}
}

func TestConfig_Validate_MissingTokenEndpoint(t *testing.T) {
	config := &Config{
		ClientId:     "client",
		ClientSecret: "secret",
		JwksUrl:      "https://example.com/certs",
		IssuerUrl:    "https://example.com/realms/test",
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing TokenEndpoint")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired")
	}
}

func TestConfig_Validate_MissingJwksUrl(t *testing.T) {
	config := &Config{
		ClientId:      "client",
		ClientSecret:  "secret",
		TokenEndpoint: "https://example.com/token",
		IssuerUrl:     "https://example.com/realms/test",
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing JwksUrl")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired")
	}
}

func TestConfig_Validate_MissingIssuerUrl(t *testing.T) {
	config := &Config{
		ClientId:      "client",
		ClientSecret:  "secret",
		TokenEndpoint: "https://example.com/token",
		JwksUrl:       "https://example.com/certs",
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing IssuerUrl")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired")
	}
}

func TestConfig_ApplyDefaults(t *testing.T) {
	config := &Config{}
	config.ApplyDefaults()

	if config.XORKey != "scmi" {
		t.Errorf("Default XORKey = %s; want scmi", config.XORKey)
	}
	if config.OTPLength != "6" {
		t.Errorf("Default OTPLength = %s; want 6", config.OTPLength)
	}
	if config.OTPClass != `\d` {
		t.Errorf("Default OTPClass = %s; want \\d", config.OTPClass)
	}
}

func TestConfig_ApplyDefaults_PreservesExisting(t *testing.T) {
	config := &Config{XORKey: "mykey", OTPLength: "8", OTPClass: "[a-zA-Z0-9]"}
	config.ApplyDefaults()

	if config.XORKey != "mykey" {
		t.Errorf("XORKey should be preserved as mykey, got %s", config.XORKey)
	}
	if config.OTPLength != "8" {
		t.Errorf("OTPLength should be preserved as 8, got %s", config.OTPLength)
	}
	if config.OTPClass != "[a-zA-Z0-9]" {
		t.Errorf("OTPClass should be preserved, got %s", config.OTPClass)
	}
}

func TestConfigError_Error(t *testing.T) {
	err := &ConfigError{Op: "stat", Path: "/path/to/file", Err: os.ErrNotExist}
	expected := "config stat /path/to/file: file does not exist"
	if err.Error() != expected {
		t.Errorf("Error() = %s; want %s", err.Error(), expected)
	}

	err = &ConfigError{Op: "get_executable", Err: errors.New("permission denied")}
	expected = "config get_executable: permission denied"
	if err.Error() != expected {
		t.Errorf("Error() = %s; want %s", err.Error(), expected)
	}
}

func TestConfigError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &ConfigError{Op: "test", Err: underlying}

	if errors.Unwrap(err) != underlying {
		t.Error("Unwrap should return underlying error")
	}
}

func TestGetDefaultConfigPath(t *testing.T) {
	path, err := getDefaultConfigPath()
	if err != nil {
		t.Fatalf("getDefaultConfigPath returned unexpected error: %v", err)
	}

	if filepath.Ext(path) != ".tml" {
		t.Errorf("path extension = %s; want .tml", filepath.Ext(path))
	}

	if !filepath.IsAbs(path) {
		t.Errorf("path should be absolute: %s", path)
	}
}

func TestLoadConfigFromFile_DirectoryPath(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := LoadConfigFromFile(tmpDir)
	if err == nil {
		t.Error("LoadConfigFromFile should return error for directory path")
	}

	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Errorf("error should be *ConfigError, got %T", err)
	}
}

func TestLoadConfigFromFile_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.tml")

	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create empty test file: %v", err)
	}

	config, err := LoadConfigFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadConfigFromFile should succeed with empty file: %v", err)
	}

	if config.ClientId != "" {
		t.Errorf("ClientId should be empty, got %s", config.ClientId)
	}
}

func TestConfig_Validate_AllFieldsEmpty(t *testing.T) {
	config := &Config{}

	err := config.Validate()
	if err == nil {
		t.Error("Validate should return error for completely empty config")
	}
	if !errors.Is(err, ErrMissingRequired) {
		t.Errorf("error should wrap ErrMissingRequired, got %v", err)
	}
}

func TestLoadConfigFromReader_TypeMismatch(t *testing.T) {
	invalidTypeTOML := `
client-id=123
client-secret="secret"
`
	_, err := LoadConfigFromReader(invalidTypeTOML)
	if err == nil {
		t.Error("LoadConfigFromReader should return error for type mismatch")
	}
}

func TestLoadConfigFromReader_UnknownFields(t *testing.T) {
	configWithUnknown := `
client-id="test-client"
client-secret="test-secret"
endpoint-token-url="https://example.com/token"
jwks-url="https://example.com/certs"
issuer-url="https://example.com/realms/test"
unknown-field="should be ignored"
`
	config, err := LoadConfigFromReader(configWithUnknown)
	if err != nil {
		t.Fatalf("LoadConfigFromReader should ignore unknown fields: %v", err)
	}

	if config.ClientId != "test-client" {
		t.Errorf("ClientId = %s; want test-client", config.ClientId)
	}
}
