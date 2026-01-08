package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestNewTokenRequest(t *testing.T) {
	tokenURL := "https://auth.example.com/token"
	clientID := "test-client"
	clientSecret := "test-secret"
	values := url.Values{
		"grant_type": {"password"},
		"username":   {"testuser"},
		"password":   {"testpass"},
	}

	req, err := newTokenRequest(tokenURL, clientID, clientSecret, values)
	if err != nil {
		t.Fatalf("newTokenRequest returned unexpected error: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("Method = %s; want POST", req.Method)
	}

	if req.URL.String() != tokenURL {
		t.Errorf("URL = %s; want %s", req.URL.String(), tokenURL)
	}

	contentType := req.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %s; want application/x-www-form-urlencoded", contentType)
	}

	// Check basic auth is set
	username, password, ok := req.BasicAuth()
	if !ok {
		t.Error("Basic auth not set")
	}
	if username != clientID {
		t.Errorf("Basic auth username = %s; want %s", username, clientID)
	}
	if password != clientSecret {
		t.Errorf("Basic auth password = %s; want %s", password, clientSecret)
	}
}

func TestNewTokenRequest_SpecialCharacters(t *testing.T) {
	// Test that special characters in client ID/secret are properly escaped
	clientID := "client+id@test"
	clientSecret := "secret&with=special"

	req, err := newTokenRequest("https://example.com/token", clientID, clientSecret, url.Values{})
	if err != nil {
		t.Fatalf("newTokenRequest returned unexpected error: %v", err)
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		t.Error("Basic auth not set")
	}
	// Basic auth should receive URL-encoded values
	if username != url.QueryEscape(clientID) {
		t.Errorf("Basic auth username = %s; want %s", username, url.QueryEscape(clientID))
	}
	if password != url.QueryEscape(clientSecret) {
		t.Errorf("Basic auth password = %s; want %s", password, url.QueryEscape(clientSecret))
	}
}

func TestNewTokenRequest_InvalidURL(t *testing.T) {
	// Test with an invalid URL that will cause http.NewRequest to fail
	_, err := newTokenRequest("://invalid-url", "client", "secret", url.Values{})
	if err == nil {
		t.Error("newTokenRequest should return error for invalid URL")
	}
}

func TestDoTokenRoundTrip_JSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "test-access-token"})
	}))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, nil)
	token, err := doTokenRoundTrip(context.Background(), req)
	if err != nil {
		t.Fatalf("doTokenRoundTrip returned unexpected error: %v", err)
	}

	if token != "test-access-token" {
		t.Errorf("token = %s; want test-access-token", token)
	}
}

func TestDoTokenRoundTrip_FormEncodedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=form-encoded-token&token_type=bearer"))
	}))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, nil)
	token, err := doTokenRoundTrip(context.Background(), req)
	if err != nil {
		t.Fatalf("doTokenRoundTrip returned unexpected error: %v", err)
	}

	if token != "form-encoded-token" {
		t.Errorf("token = %s; want form-encoded-token", token)
	}
}

func TestDoTokenRoundTrip_TextPlainResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("access_token=text-plain-token"))
	}))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, nil)
	token, err := doTokenRoundTrip(context.Background(), req)
	if err != nil {
		t.Fatalf("doTokenRoundTrip returned unexpected error: %v", err)
	}

	if token != "text-plain-token" {
		t.Errorf("token = %s; want text-plain-token", token)
	}
}

func TestDoTokenRoundTrip_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type": "bearer"}`))
	}))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, nil)
	_, err := doTokenRoundTrip(context.Background(), req)
	if err == nil {
		t.Error("doTokenRoundTrip should return error when access_token is missing")
	}

	if !strings.Contains(err.Error(), "missing access_token") {
		t.Errorf("error should mention missing access_token, got: %v", err)
	}
}

func TestDoTokenRoundTrip_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL, nil)
	_, err := doTokenRoundTrip(context.Background(), req)
	if err == nil {
		t.Error("doTokenRoundTrip should return error for invalid JSON")
	}
}

func TestDoTokenRoundTrip_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{"BadRequest", http.StatusBadRequest, `{"error": "invalid_request"}`},
		{"Unauthorized", http.StatusUnauthorized, `{"error": "invalid_client"}`},
		{"Forbidden", http.StatusForbidden, `{"error": "access_denied"}`},
		{"InternalServerError", http.StatusInternalServerError, `{"error": "server_error"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			req, _ := http.NewRequest("POST", server.URL, nil)
			_, err := doTokenRoundTrip(context.Background(), req)
			if err == nil {
				t.Errorf("doTokenRoundTrip should return error for status %d", tt.statusCode)
			}

			rErr, ok := err.(*retrieveError)
			if !ok {
				t.Errorf("error should be *retrieveError, got %T", err)
			}
			if rErr.Response.StatusCode != tt.statusCode {
				t.Errorf("Response.StatusCode = %d; want %d", rErr.Response.StatusCode, tt.statusCode)
			}
			if string(rErr.Body) != tt.body {
				t.Errorf("Body = %s; want %s", string(rErr.Body), tt.body)
			}
		})
	}
}

func TestDoTokenRoundTrip_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response that should be canceled
		select {}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequest("POST", server.URL, nil)
	_, err := doTokenRoundTrip(ctx, req)
	if err == nil {
		t.Error("doTokenRoundTrip should return error when context is canceled")
	}
}

func TestRetrieveToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Method = %s; want POST", r.Method)
		}

		username, password, ok := r.BasicAuth()
		if !ok {
			t.Error("Basic auth not set")
		}
		if username != "test-client" {
			t.Errorf("Basic auth username = %s; want test-client", username)
		}
		if password != "test-secret" {
			t.Errorf("Basic auth password = %s; want test-secret", password)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "retrieved-token"})
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	token, err := retrieveToken(context.Background(), config, url.Values{"grant_type": {"password"}})
	if err != nil {
		t.Fatalf("retrieveToken returned unexpected error: %v", err)
	}

	if token != "retrieved-token" {
		t.Errorf("token = %s; want retrieved-token", token)
	}
}

func TestRetrieveToken_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer server.Close()

	config := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "wrong-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	_, err := retrieveToken(context.Background(), config, url.Values{"grant_type": {"password"}})
	if err == nil {
		t.Error("retrieveToken should return error for unauthorized response")
	}

	_, ok := err.(*retrieveError)
	if !ok {
		t.Errorf("error should be *retrieveError, got %T", err)
	}
}

func TestPasswordCredentialsTokenEx_BasicRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		// Verify required fields
		if r.PostForm.Get("grant_type") != "password" {
			t.Errorf("grant_type = %s; want password", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("username") != "testuser" {
			t.Errorf("username = %s; want testuser", r.PostForm.Get("username"))
		}
		if r.PostForm.Get("password") != "testpass" {
			t.Errorf("password = %s; want testpass", r.PostForm.Get("password"))
		}

		// Verify OTP and scope are not set
		if r.PostForm.Get("totp") != "" {
			t.Errorf("totp should not be set, got: %s", r.PostForm.Get("totp"))
		}
		if r.PostForm.Get("scope") != "" {
			t.Errorf("scope should not be set, got: %s", r.PostForm.Get("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "basic-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	token, err := passwordCredentialsTokenEx(context.Background(), config, "testuser", "testpass", "", "", nil)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "basic-token" {
		t.Errorf("token = %s; want basic-token", token)
	}
}

func TestPasswordCredentialsTokenEx_WithOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		if r.PostForm.Get("totp") != "123456" {
			t.Errorf("totp = %s; want 123456", r.PostForm.Get("totp"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "otp-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	token, err := passwordCredentialsTokenEx(context.Background(), config, "user", "pass", "123456", "", nil)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "otp-token" {
		t.Errorf("token = %s; want otp-token", token)
	}
}

func TestPasswordCredentialsTokenEx_WithScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		if r.PostForm.Get("scope") != "openid profile" {
			t.Errorf("scope = %s; want 'openid profile'", r.PostForm.Get("scope"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "scoped-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	token, err := passwordCredentialsTokenEx(context.Background(), config, "user", "pass", "", "openid profile", nil)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "scoped-token" {
		t.Errorf("token = %s; want scoped-token", token)
	}
}

func TestPasswordCredentialsTokenEx_WithExtraParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		if r.PostForm.Get("custom_param") != "custom_value" {
			t.Errorf("custom_param = %s; want custom_value", r.PostForm.Get("custom_param"))
		}
		if r.PostForm.Get("audience") != "https://api.example.com" {
			t.Errorf("audience = %s; want https://api.example.com", r.PostForm.Get("audience"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "extra-params-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	extraParams := url.Values{
		"custom_param": {"custom_value"},
		"audience":     {"https://api.example.com"},
	}

	token, err := passwordCredentialsTokenEx(context.Background(), config, "user", "pass", "", "", extraParams)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "extra-params-token" {
		t.Errorf("token = %s; want extra-params-token", token)
	}
}

func TestPasswordCredentialsTokenEx_WithAllOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}

		// Verify all fields are set
		if r.PostForm.Get("grant_type") != "password" {
			t.Errorf("grant_type = %s; want password", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("username") != "fulluser" {
			t.Errorf("username = %s; want fulluser", r.PostForm.Get("username"))
		}
		if r.PostForm.Get("password") != "fullpass" {
			t.Errorf("password = %s; want fullpass", r.PostForm.Get("password"))
		}
		if r.PostForm.Get("totp") != "654321" {
			t.Errorf("totp = %s; want 654321", r.PostForm.Get("totp"))
		}
		if r.PostForm.Get("scope") != "vpn_roles" {
			t.Errorf("scope = %s; want vpn_roles", r.PostForm.Get("scope"))
		}
		if r.PostForm.Get("extra") != "value" {
			t.Errorf("extra = %s; want value", r.PostForm.Get("extra"))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "full-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	token, err := passwordCredentialsTokenEx(
		context.Background(),
		config,
		"fulluser",
		"fullpass",
		"654321",
		"vpn_roles",
		url.Values{"extra": {"value"}},
	)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "full-token" {
		t.Errorf("token = %s; want full-token", token)
	}
}

func TestPasswordCredentialsTokenEx_NilExtraParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenJSON{AccessToken: "nil-params-token"})
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	// Explicitly pass nil for parameters
	token, err := passwordCredentialsTokenEx(context.Background(), config, "user", "pass", "", "", nil)
	if err != nil {
		t.Fatalf("passwordCredentialsTokenEx returned unexpected error: %v", err)
	}

	if token != "nil-params-token" {
		t.Errorf("token = %s; want nil-params-token", token)
	}
}

func TestPasswordCredentialsTokenEx_AuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid_grant", "error_description": "Invalid user credentials"}`))
	}))
	defer server.Close()

	config := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	_, err := passwordCredentialsTokenEx(context.Background(), config, "user", "wrongpass", "", "", nil)
	if err == nil {
		t.Error("passwordCredentialsTokenEx should return error for invalid credentials")
	}

	rErr, ok := err.(*retrieveError)
	if !ok {
		t.Errorf("error should be *retrieveError, got %T", err)
	}
	if rErr.Response.StatusCode != http.StatusUnauthorized {
		t.Errorf("Response.StatusCode = %d; want %d", rErr.Response.StatusCode, http.StatusUnauthorized)
	}
}

func TestRetrieveError_Error(t *testing.T) {
	resp := &http.Response{
		Status:     "401 Unauthorized",
		StatusCode: http.StatusUnauthorized,
	}
	body := []byte(`{"error": "invalid_client"}`)

	err := &retrieveError{
		Response: resp,
		Body:     body,
	}

	expected := `oauth2: cannot fetch token: 401 Unauthorized
Response: {"error": "invalid_client"}`

	if err.Error() != expected {
		t.Errorf("Error() = %q; want %q", err.Error(), expected)
	}
}

func TestRetrieveError_ErrorWithEmptyBody(t *testing.T) {
	resp := &http.Response{
		Status:     "500 Internal Server Error",
		StatusCode: http.StatusInternalServerError,
	}

	err := &retrieveError{
		Response: resp,
		Body:     []byte{},
	}

	if !strings.Contains(err.Error(), "500 Internal Server Error") {
		t.Errorf("Error() should contain status, got: %s", err.Error())
	}
}