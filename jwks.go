package main

// JWKS retrieval and JWK-to-public-key decoding, hand-rolled on the standard library.
//
// PR #34 proposed github.com/MicahParks/keyfunc/v3 for this. It works, but it pulls
// keyfunc, jwkset and golang.org/x/time, and would add the first `// indirect` entries
// go.sum has ever carried — against go-style.md's "reach for the stdlib first" and "the
// graph is flat, with no indirect entries in go.sum; keep it that way". All the library
// adds over the code below is JWK decoding: golang-jwt/jwt/v5 is already a direct
// dependency and performs the signature verification itself once handed a public key.
//
// RSA and ECDSA are decoded here so the RS*/ES*/Ed25519 families that the alternative
// signing methods rely on all keep working; dropping either would silently break a realm
// signing with it.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSError represents a failure to retrieve or decode a JWK Set.
type JWKSError struct {
	Op  string // Operation that failed (e.g., "fetch", "decode", "keyfunc")
	URL string // JWKS endpoint, empty for decode-only failures
	Err error
}

func (e *JWKSError) Error() string {
	if e.URL == "" {
		return fmt.Sprintf("jwks %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("jwks %s %s: %v", e.Op, e.URL, e.Err)
}

func (e *JWKSError) Unwrap() error { return e.Err }

// jwk is one key of a JWK Set. Only the members needed to rebuild a public key are
// decoded; everything else Keycloak publishes (x5c, x5t, key_ops) is ignored.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// b64uint decodes a base64url-encoded JWK member. JWK integers are unpadded
// (RFC 7517 §3), so RawURLEncoding is the correct decoder and StdEncoding is not.
func b64uint(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// jwkPublicKey rebuilds the public key a JWK describes.
func jwkPublicKey(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, fmt.Errorf("rsa modulus: %w", err)
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa exponent: %w", err)
		}
		if len(n) == 0 || len(e) == 0 {
			return nil, fmt.Errorf("rsa key is missing n or e")
		}
		// The exponent is a big-endian integer, almost always 65537 ("AQAB").
		if len(e) > 8 {
			return nil, fmt.Errorf("rsa exponent is implausibly large (%d bytes)", len(e))
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil

	case "EC":
		curve, size, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, fmt.Errorf("ec x: %w", err)
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, fmt.Errorf("ec y: %w", err)
		}
		// Both coordinates are fixed-width for the curve; a wrong width means the key
		// is not the curve it claims to be.
		if len(x) != size || len(y) != size {
			return nil, fmt.Errorf("ec coordinates are %d/%d bytes, want %d for %s", len(x), len(y), size, k.Crv)
		}
		// SEC 1 uncompressed point, 0x04 || X || Y. Going through
		// ParseUncompressedPublicKey rather than building the struct by hand also
		// checks the point is actually on the curve, and building it by hand is
		// deprecated as of Go 1.26.
		point := make([]byte, 0, 1+2*size)
		point = append(point, 4)
		point = append(point, x...)
		point = append(point, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("ec point: %w", err)
		}
		return pub, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, fmt.Errorf("ed25519 x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ed25519 key is %d bytes, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// ecCurve maps a JWK curve name to its curve and coordinate width in bytes.
func ecCurve(crv string) (elliptic.Curve, int, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		// 521 bits rounds up to 66 bytes.
		return elliptic.P521(), 66, nil
	}
	return nil, 0, fmt.Errorf("unsupported EC curve %q", crv)
}

// parseJWKS decodes a JWK Set into public keys indexed by key id. Keys marked for
// encryption are skipped: Keycloak publishes its RSA-OAEP key at the same endpoint,
// and it must never enter the signature-verification pool. A key whose type this
// build cannot decode is skipped rather than failing the whole set, so one unknown
// algorithm does not lock every user out.
func parseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, &JWKSError{Op: "decode", Err: err}
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := jwkPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, &JWKSError{Op: "decode", Err: fmt.Errorf("no usable signing keys in JWK Set")}
	}
	return keys, nil
}

// fetchJWKS retrieves the raw JWK Set document. The client is a parameter so tests can
// inject an httptest server's client; production passes one with a timeout.
func fetchJWKS(jwksURL string, client *http.Client) ([]byte, error) {
	if jwksURL == "" {
		return nil, &JWKSError{Op: "fetch", Err: fmt.Errorf("jwks-url is not configured")}
	}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, &JWKSError{Op: "fetch", URL: jwksURL, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &JWKSError{Op: "fetch", URL: jwksURL, Err: fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)}
	}
	// Same 1 MiB cap oauth2ex.go applies to the token response.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &JWKSError{Op: "fetch", URL: jwksURL, Err: err}
	}
	return body, nil
}

// newJWKSKeyfunc returns a jwt.Keyfunc that resolves a token's `kid` against the set.
//
// It also refuses a token whose signing method does not match the key type it selected.
// That check is the defence against algorithm confusion — without it a token could name
// a family whose verification the chosen key was never meant to satisfy
// (https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).
func newJWKSKeyfunc(keys map[string]crypto.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		pub, ok := keys[kid]
		if !ok {
			// A set published without key ids is indexed under the empty string.
			if pub, ok = keys[""]; !ok {
				return nil, &JWKSError{Op: "keyfunc", Err: fmt.Errorf("no key for kid %q", kid)}
			}
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
			if _, ok := pub.(*rsa.PublicKey); !ok {
				return nil, &JWKSError{Op: "keyfunc", Err: fmt.Errorf("alg %s does not match key type for kid %q", token.Method.Alg(), kid)}
			}
		case *jwt.SigningMethodECDSA:
			if _, ok := pub.(*ecdsa.PublicKey); !ok {
				return nil, &JWKSError{Op: "keyfunc", Err: fmt.Errorf("alg %s does not match key type for kid %q", token.Method.Alg(), kid)}
			}
		case *jwt.SigningMethodEd25519:
			if _, ok := pub.(ed25519.PublicKey); !ok {
				return nil, &JWKSError{Op: "keyfunc", Err: fmt.Errorf("alg %s does not match key type for kid %q", token.Method.Alg(), kid)}
			}
		default:
			return nil, &JWKSError{Op: "keyfunc", Err: fmt.Errorf("unsupported signing method %s", token.Method.Alg())}
		}
		return pub, nil
	}
}
