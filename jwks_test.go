package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// b64 encodes a JWK member the way RFC 7517 requires: base64url, unpadded.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWKS(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	e := big.NewInt(int64(pub.E)).Bytes()
	return []byte(fmt.Sprintf(`{"keys":[{"kid":%q,"kty":"RSA","use":"sig","alg":"RS256","n":%q,"e":%q}]}`,
		kid, b64(pub.N.Bytes()), b64(e)))
}

func TestParseJWKS_RSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &priv.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	got, ok := keys["sig-1"].(*rsa.PublicKey)
	if !ok {
		t.Fatalf("keys[sig-1] = %T; want *rsa.PublicKey", keys["sig-1"])
	}
	if got.N.Cmp(priv.N) != 0 || got.E != priv.E {
		t.Errorf("decoded key does not match the original modulus/exponent")
	}
}

func TestParseJWKS_ECKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	// PublicKey.Bytes() is the uncompressed point 0x04 || X || Y; reading .X/.Y directly
	// is deprecated as of Go 1.26.
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes returned unexpected error: %v", err)
	}
	body := []byte(fmt.Sprintf(`{"keys":[{"kid":"ec-1","kty":"EC","use":"sig","crv":"P-256","x":%q,"y":%q}]}`,
		b64(point[1:33]), b64(point[33:])))
	keys, err := parseJWKS(body)
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	got, ok := keys["ec-1"].(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("keys[ec-1] = %T; want *ecdsa.PublicKey", keys["ec-1"])
	}
	gotPoint, err := got.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes returned unexpected error: %v", err)
	}
	if !bytes.Equal(gotPoint, point) {
		t.Errorf("decoded EC point does not match the original")
	}
}

func TestParseJWKS_Ed25519Key(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	body := []byte(fmt.Sprintf(`{"keys":[{"kid":"ed-1","kty":"OKP","use":"sig","crv":"Ed25519","x":%q}]}`, b64(pub)))
	keys, err := parseJWKS(body)
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	if _, ok := keys["ed-1"].(ed25519.PublicKey); !ok {
		t.Fatalf("keys[ed-1] = %T; want ed25519.PublicKey", keys["ed-1"])
	}
}

// Keycloak publishes its RSA-OAEP encryption key at the same endpoint. It must never
// reach the verification pool.
func TestParseJWKS_SkipsEncryptionKeys(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	body := []byte(fmt.Sprintf(
		`{"keys":[{"kid":"enc-1","kty":"RSA","use":"enc","n":%q,"e":%q},{"kid":"sig-1","kty":"RSA","use":"sig","n":%q,"e":%q}]}`,
		b64(priv.N.Bytes()), b64(big.NewInt(int64(priv.E)).Bytes()),
		b64(priv.N.Bytes()), b64(big.NewInt(int64(priv.E)).Bytes())))
	keys, err := parseJWKS(body)
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	if _, ok := keys["enc-1"]; ok {
		t.Errorf("keys[enc-1] is present; want the enc-use key skipped")
	}
	if _, ok := keys["sig-1"]; !ok {
		t.Errorf("keys[sig-1] is missing; want the sig-use key kept")
	}
}

func TestParseJWKS_InvalidJSON(t *testing.T) {
	_, err := parseJWKS([]byte("not json"))
	var jerr *JWKSError
	if !errors.As(err, &jerr) {
		t.Fatalf("parseJWKS error = %T; want *JWKSError", err)
	}
	if jerr.Op != "decode" {
		t.Errorf("Op = %s; want decode", jerr.Op)
	}
}

func TestParseJWKS_NoUsableKeys(t *testing.T) {
	_, err := parseJWKS([]byte(`{"keys":[{"kid":"x","kty":"UNKNOWN"}]}`))
	var jerr *JWKSError
	if !errors.As(err, &jerr) {
		t.Fatalf("parseJWKS error = %T; want *JWKSError", err)
	}
}

// The true positive: a genuine token signed by the advertised key must verify. Without
// this, a keyfunc that refused everything would pass every negative test below.
func TestNewJWKSKeyfunc_VerifiesGenuineToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &priv.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "alice"})
	tok.Header["kid"] = "sig-1"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString returned unexpected error: %v", err)
	}
	parsed, err := jwt.Parse(signed, newJWKSKeyfunc(keys))
	if err != nil {
		t.Fatalf("Parse returned unexpected error: %v", err)
	}
	if !parsed.Valid {
		t.Errorf("parsed.Valid = false; want true")
	}
}

// A token signed by a key the IdP never published must be refused. This is the defect the
// whole change exists to fix: before it, jwt.Parse's error was discarded and any signature
// was accepted.
func TestNewJWKSKeyfunc_RejectsAttackerSignedToken(t *testing.T) {
	real, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &real.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "mallory"})
	tok.Header["kid"] = "sig-1" // claims the real key id
	signed, err := tok.SignedString(attacker)
	if err != nil {
		t.Fatalf("SignedString returned unexpected error: %v", err)
	}
	parsed, err := jwt.Parse(signed, newJWKSKeyfunc(keys))
	if err == nil {
		t.Fatalf("Parse error = nil; want a signature failure")
	}
	if parsed != nil && parsed.Valid {
		t.Errorf("parsed.Valid = true; want false for an attacker-signed token")
	}
}

func TestNewJWKSKeyfunc_RejectsUnknownKid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &priv.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "alice"})
	tok.Header["kid"] = "sig-999"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString returned unexpected error: %v", err)
	}
	if _, err = jwt.Parse(signed, newJWKSKeyfunc(keys)); err == nil {
		t.Errorf("Parse error = nil; want a rejection for an unknown kid")
	}
}

// Algorithm confusion: a token naming an EC algorithm must not be verified against an
// RSA key, whatever kid it presents.
func TestNewJWKSKeyfunc_RejectsAlgKeyTypeMismatch(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &rsaPriv.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "mallory"})
	tok.Header["kid"] = "sig-1"
	signed, err := tok.SignedString(ecPriv)
	if err != nil {
		t.Fatalf("SignedString returned unexpected error: %v", err)
	}
	if _, err = jwt.Parse(signed, newJWKSKeyfunc(keys)); err == nil {
		t.Errorf("Parse error = nil; want a rejection for an alg/key-type mismatch")
	}
}

// The classic algorithm-confusion attack: the token names HMAC and is signed with the
// RSA public key's own bytes as the shared secret. The keyfunc must refuse the method
// outright rather than hand an asymmetric key to a symmetric verifier.
func TestNewJWKSKeyfunc_RejectsHMACToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned unexpected error: %v", err)
	}
	keys, err := parseJWKS(rsaJWKS(t, "sig-1", &priv.PublicKey))
	if err != nil {
		t.Fatalf("parseJWKS returned unexpected error: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "mallory"})
	tok.Header["kid"] = "sig-1"
	signed, err := tok.SignedString(priv.N.Bytes())
	if err != nil {
		t.Fatalf("SignedString returned unexpected error: %v", err)
	}
	_, err = jwt.Parse(signed, newJWKSKeyfunc(keys))
	if err == nil {
		t.Fatalf("Parse error = nil; want the HMAC method refused")
	}
	var jerr *JWKSError
	if !errors.As(err, &jerr) {
		t.Errorf("Parse error = %v; want it to wrap *JWKSError from the keyfunc", err)
	}
}

func TestFetchJWKS_Success(t *testing.T) {
	body := `{"keys":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	got, err := fetchJWKS(server.URL, server.Client())
	if err != nil {
		t.Fatalf("fetchJWKS returned unexpected error: %v", err)
	}
	if string(got) != body {
		t.Errorf("fetchJWKS = %s; want %s", got, body)
	}
}

func TestFetchJWKS_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := fetchJWKS(server.URL, server.Client())
	var jerr *JWKSError
	if !errors.As(err, &jerr) {
		t.Fatalf("fetchJWKS error = %T; want *JWKSError", err)
	}
	if jerr.Op != "fetch" {
		t.Errorf("Op = %s; want fetch", jerr.Op)
	}
}

func TestFetchJWKS_EmptyURL(t *testing.T) {
	_, err := fetchJWKS("", http.DefaultClient)
	var jerr *JWKSError
	if !errors.As(err, &jerr) {
		t.Fatalf("fetchJWKS error = %T; want *JWKSError", err)
	}
}
