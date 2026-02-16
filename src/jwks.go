package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

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
