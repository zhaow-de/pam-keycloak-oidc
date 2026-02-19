package main

import (
	"regexp"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestOTPPasswordPattern_Default(t *testing.T) {
	// Default OTP: 6 digits (\d{6})
	pattern := regexp.MustCompile(`^(.+)(\d{6})$`)

	match := pattern.FindStringSubmatch("MyPassword123456")
	if match == nil {
		t.Fatal("Default OTP pattern should match password+6digits")
	}
	if match[1] != "MyPassword" {
		t.Errorf("Password part = %s; want MyPassword", match[1])
	}
	if match[2] != "123456" {
		t.Errorf("OTP part = %s; want 123456", match[2])
	}

	// Only digits, no password part (5 digits — doesn't match 6)
	match = pattern.FindStringSubmatch("12345")
	if match != nil {
		t.Error("5-digit input should not match 6-digit OTP pattern")
	}

	// Exactly 6 digits — the greedy (.+) requires at least 1 char for password
	match = pattern.FindStringSubmatch("123456")
	if match != nil {
		t.Error("Exactly 6 digits with no password should not match (.+) pattern")
	}
}

func TestOTPPasswordPattern_CustomLength(t *testing.T) {
	// Custom OTP: 8 digits
	otpClass := `\d`
	otpLength := "8"
	pattern := regexp.MustCompile(`^(.+)(` + otpClass + `{` + otpLength + `})$`)

	match := pattern.FindStringSubmatch("MyPassword12345678")
	if match == nil {
		t.Fatal("Custom OTP pattern should match password+8digits")
	}
	if match[1] != "MyPassword" {
		t.Errorf("Password part = %s; want MyPassword", match[1])
	}
	if match[2] != "12345678" {
		t.Errorf("OTP part = %s; want 12345678", match[2])
	}
}

func TestOTPPasswordPattern_AlphanumericClass(t *testing.T) {
	// Custom OTP: 6 alphanumeric characters
	otpClass := `[a-zA-Z0-9]`
	otpLength := "6"
	pattern := regexp.MustCompile(`^(.+)(` + otpClass + `{` + otpLength + `})$`)

	match := pattern.FindStringSubmatch("MyPasswordAbC123")
	if match == nil {
		t.Fatal("Alphanumeric OTP pattern should match")
	}
	if match[2] != "AbC123" {
		t.Errorf("OTP part = %s; want AbC123", match[2])
	}
}

func TestOTPPasswordPattern_InvalidRegex(t *testing.T) {
	// Verify that invalid regex class is caught by regexp.Compile
	otpClass := `[invalid`
	otpLength := "6"
	_, err := regexp.Compile(`^(.+)(` + otpClass + `{` + otpLength + `})$`)
	if err == nil {
		t.Error("Invalid regex class should produce compilation error")
	}
}

func TestCheckRoleAuthorization(t *testing.T) {
	tests := []struct {
		name          string
		scope         string
		requiredRoles []string
		matchMode     string
		claims        jwt.MapClaims
		want          bool
	}{
		// Single role backward compat
		{
			name:          "single role match",
			scope:         "pam_roles",
			requiredRoles: []string{"admin"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"admin", "user"}},
			want:          true,
		},
		{
			name:          "single role no match",
			scope:         "pam_roles",
			requiredRoles: []string{"admin"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"user", "viewer"}},
			want:          false,
		},
		// OR mode (any)
		{
			name:          "any: match first role",
			scope:         "pam_roles",
			requiredRoles: []string{"admin", "ssh-user"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"admin"}},
			want:          true,
		},
		{
			name:          "any: match second role",
			scope:         "pam_roles",
			requiredRoles: []string{"admin", "ssh-user"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"ssh-user"}},
			want:          true,
		},
		{
			name:          "any: no match",
			scope:         "pam_roles",
			requiredRoles: []string{"admin", "ssh-user"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"viewer"}},
			want:          false,
		},
		// AND mode (all)
		{
			name:          "all: all present",
			scope:         "pam_roles",
			requiredRoles: []string{"developer", "ssh-access"},
			matchMode:     "all",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"developer", "ssh-access", "viewer"}},
			want:          true,
		},
		{
			name:          "all: partial match",
			scope:         "pam_roles",
			requiredRoles: []string{"developer", "ssh-access"},
			matchMode:     "all",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"developer"}},
			want:          false,
		},
		{
			name:          "all: none match",
			scope:         "pam_roles",
			requiredRoles: []string{"developer", "ssh-access"},
			matchMode:     "all",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"viewer"}},
			want:          false,
		},
		// Edge cases
		{
			name:          "empty required roles",
			scope:         "pam_roles",
			requiredRoles: []string{},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": []interface{}{"admin"}},
			want:          false,
		},
		{
			name:          "missing scope in claims",
			scope:         "pam_roles",
			requiredRoles: []string{"admin"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"other_claim": "value"},
			want:          false,
		},
		{
			name:          "scope is not an array",
			scope:         "pam_roles",
			requiredRoles: []string{"admin"},
			matchMode:     "any",
			claims:        jwt.MapClaims{"pam_roles": "not-an-array"},
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkRoleAuthorization(tt.claims, tt.scope, tt.requiredRoles, tt.matchMode)
			if got != tt.want {
				t.Errorf("checkRoleAuthorization() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestOTPPasswordPattern_SpecialCharsInPassword(t *testing.T) {
	// Password with special characters followed by 6-digit OTP
	pattern := regexp.MustCompile(`^(.+)(\d{6})$`)

	tests := []struct {
		input    string
		password string
		otp      string
	}{
		{"P@ss!word123456", "P@ss!word", "123456"},
		{"test!!123456", "test!!", "123456"},
		{"p@$$w0rd!!##123456", "p@$$w0rd!!##", "123456"},
		{"a 123456", "a ", "123456"},
	}

	for _, tt := range tests {
		match := pattern.FindStringSubmatch(tt.input)
		if match == nil {
			t.Errorf("Pattern should match %q", tt.input)
			continue
		}
		if match[1] != tt.password {
			t.Errorf("For %q: password = %s; want %s", tt.input, match[1], tt.password)
		}
		if match[2] != tt.otp {
			t.Errorf("For %q: otp = %s; want %s", tt.input, match[2], tt.otp)
		}
	}
}
