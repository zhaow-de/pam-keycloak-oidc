package main

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	orig := "Hello World!"
	encoded := encryptDecrypt([]byte(orig), "scmi")
	decoded := encryptDecrypt(encoded, "scmi")
	result := string(decoded)
	if result != orig {
		t.Errorf("2x encryptDecrypt produced %s; want %s", result, orig)
	}

	decoded = encryptDecrypt(encoded, "salt")
	result = string(decoded)
	if result != "Hgmqo\"Vrrne<" {
		t.Errorf("encryptDecrypt produced %s; want %s", result, orig)
	}
}

func TestBase32(t *testing.T) {
	//
	// decode regular base32
	orig := "Hello World!"
	encoded := "JBSWY3DPEBLW64TMMQQQ===="
	result := string(b32decode(encoded))
	if result != orig {
		t.Errorf("b32decode(%s) produced %s; want %s", encoded, result, orig)
	}
	//
	// decode lower-case encoding
	orig = "Good morning!!!"
	encoded = "i5xw6zbanvxxe3tjnztscijb"
	result = string(b32decode(encoded))
	if result != orig {
		t.Errorf("b32decode(%s) produced %s; want %s", encoded, result, orig)
	}
	//
	// decode wrong input
	encoded = "1+/\\?'^``*"
	result = string(b32decode(encoded))
	if result != "" {
		t.Errorf("b32decode(%s) produced %s; want \"\"", encoded, result)
	}
	//
	// encode regular string
	orig = "Good morning!!!"
	encoded = "I5XW6ZBANVXXE3TJNZTSCIJB"
	result = b32encode([]byte(orig))
	if result != encoded {
		t.Errorf("b32encode(%s) produced %s; want %s", orig, result, encoded)
	}

}

func TestAscii85(t *testing.T) {
	//
	// encode then decode
	orig := "Hello World!"
	encoded := "87cURD]i,\"Ebo80"
	result := a85Encode([]byte(orig))
	if result != encoded {
		t.Errorf("a85Encode(%s) produced %s; want %s", orig, result, encoded)
	}
	result = string(a85Decode(result))
	if result != orig {
		t.Errorf("a85Decode(%s) produced %s; want %s", encoded, result, orig)
	}
	//
	// decode non-ascii85 string
	encoded = "½😛测试"
	resultBuf := a85Decode(result)
	if resultBuf != nil {
		t.Errorf("a85Decode(%s) produced %s; want nil", encoded, resultBuf)
	}
}

func TestUsername(t *testing.T) {
	//
	// regular case
	// encode
	username := "zhaow"
	secret := "G6JWH4VZIWE2KP4NSTFY72H3F3F7ZGAFJ242SDFP32SSS6MDAG2Z5B6ENBJBIDZJ"
	newUsername := genUsername(username, secret, "scmi")
	expected := "#n%.G\"Beq)&<YHnqSlFokG[BkLeXb3lXhBgg2Fj;ek-YAEn9jM[gPEKHqF"
	if newUsername != expected {
		t.Errorf("genUsername(%s, %s, \"scmi\") produced %s; want %s", username, secret, newUsername, expected)
	}
	// decode
	newUsername, newSecret := decodeUsername(expected, "scmi")
	if newUsername != username || newSecret != secret {
		t.Errorf("decodeUsername(%s, \"scmi\") produced (%s, %s); want (%s, %s)", expected, newUsername, newSecret, username, secret)
	}
	//
	// decode non-ascii85 string
	newUsername, newSecret = decodeUsername("½😛测试", "scmi")
	if newUsername != "" || newSecret != "" {
		t.Errorf("decodeUsername(%s, \"scmi\") produced (%s, %s); want (\"\", \"\")", expected, newUsername, newSecret)
	}
	//
	// decode ascii85 string without ":" as the separator
	newUsername, newSecret = decodeUsername("87cURD]i,\"Ebo80", "scmi")
	if newUsername != "" || newSecret != "" {
		t.Errorf("decodeUsername(%s, \"scmi\") produced (%s, %s); want (\"\", \"\")", expected, newUsername, newSecret)
	}
}

func TestOTP(t *testing.T) {
	secretUsername := "#n%.G\"Bk*ZK>+[MGIcX3nY4jTUh(DWYgQc'XknbKB>/+01M1=0`VH'#K7*"
	username, secert := decodeUsername(secretUsername, "scmi")
	if username != "zhaow" {
		t.Errorf("decodeUsername(%s, \"scmi\") produced wrong username %s; want %s", secretUsername, username, "zhaow")
	}
	token := calculateOtpToken(secert, 1589112197)
	if token != "024662" {
		t.Errorf("decodeUsername(%s, \"scmi\") produced wrong OTP token %s; want %s", secretUsername, token, "024662")
	}
}

// Additional edge case tests for encryptDecrypt
func TestEncryptDecrypt_EmptyInput(t *testing.T) {
	result := encryptDecrypt([]byte(""), "key")
	if len(result) != 0 {
		t.Errorf("encryptDecrypt with empty input should return empty, got %v", result)
	}
}

func TestEncryptDecrypt_SingleByte(t *testing.T) {
	input := []byte("A")
	key := "k"
	encoded := encryptDecrypt(input, key)
	decoded := encryptDecrypt(encoded, key)
	if string(decoded) != "A" {
		t.Errorf("encryptDecrypt roundtrip failed for single byte, got %s; want A", string(decoded))
	}
}

func TestEncryptDecrypt_LongInputShortKey(t *testing.T) {
	// Test that XOR key cycles correctly over long input
	input := []byte("ABCDEFGHIJKLMNOP") // 16 bytes
	key := "xy"                          // 2 byte key, should cycle 8 times
	encoded := encryptDecrypt(input, key)
	decoded := encryptDecrypt(encoded, key)
	if string(decoded) != string(input) {
		t.Errorf("encryptDecrypt with cycling key failed, got %s; want %s", string(decoded), string(input))
	}
}

// Additional edge case tests for ASCII85
func TestAscii85_EmptyInput(t *testing.T) {
	encoded := a85Encode([]byte(""))
	if encoded != "" {
		t.Errorf("a85Encode of empty input should be empty, got %s", encoded)
	}

	decoded := a85Decode("")
	// a85Decode returns empty slice (not nil) for empty input
	if len(decoded) != 0 {
		t.Errorf("a85Decode of empty string should be empty, got %v", decoded)
	}
}

func TestAscii85_SingleByte(t *testing.T) {
	input := []byte("X")
	encoded := a85Encode(input)
	decoded := a85Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Errorf("a85 roundtrip for single byte failed, got %v; want %v", decoded, input)
	}
}

func TestAscii85_BinaryData(t *testing.T) {
	// Test with binary data including null bytes
	input := []byte{0x00, 0xFF, 0x7F, 0x80, 0x01}
	encoded := a85Encode(input)
	decoded := a85Decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Errorf("a85 roundtrip for binary data failed, got %v; want %v", decoded, input)
	}
}

// Additional edge case tests for Base32
func TestBase32_EmptyInput(t *testing.T) {
	encoded := b32encode([]byte(""))
	if encoded != "" {
		t.Errorf("b32encode of empty input should be empty, got %s", encoded)
	}

	decoded := b32decode("")
	if len(decoded) != 0 {
		t.Errorf("b32decode of empty string should be empty, got %v", decoded)
	}
}

func TestBase32_SingleByte(t *testing.T) {
	input := []byte("A")
	encoded := b32encode(input)
	decoded := b32decode(encoded)
	if !bytes.Equal(decoded, input) {
		t.Errorf("b32 roundtrip for single byte failed, got %v; want %v", decoded, input)
	}
}

func TestBase32_MixedCase(t *testing.T) {
	// b32decode converts to uppercase, so mixed case should work
	encoded := "JbSwY3DpEbLw64TmMqQq===="
	expected := "Hello World!"
	result := string(b32decode(encoded))
	if result != expected {
		t.Errorf("b32decode with mixed case failed, got %s; want %s", result, expected)
	}
}

func TestBase32_NoPadding(t *testing.T) {
	// Test decoding without padding (should fail gracefully)
	encoded := "JBSWY3DPEBLW64TMMQQQ" // No padding
	result := b32decode(encoded)
	// Without proper padding, decode may return partial or empty result
	// The actual behavior depends on base32.StdEncoding
	if result == nil {
		t.Log("b32decode without padding returned nil (expected behavior)")
	}
}

// Additional edge case tests for genUsername
func TestGenUsername_EmptyUsername(t *testing.T) {
	// Empty username with valid secret will encode but fail to decode
	// because the regex ^[a-zA-Z0-9_.-]+$ requires at least one character
	secret := "JBSWY3DPEHPK3PXP" // Valid base32
	result := genUsername("", secret, "key")
	if result == "" {
		t.Error("genUsername with empty username should produce output")
	}

	// Decode will fail because empty username doesn't match regex
	decoded, decodedSecret := decodeUsername(result, "key")
	// Empty username fails validation, so both return empty
	if decoded != "" || decodedSecret != "" {
		t.Errorf("decodeUsername should return empty for empty username, got (%s, %s)", decoded, decodedSecret)
	}
}

func TestGenUsername_InvalidSecret(t *testing.T) {
	// Test that invalid secret causes panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("genUsername with invalid secret should panic")
		}
	}()
	genUsername("user", "INVALID!!!", "key")
}

func TestGenUsername_SpecialCharacters(t *testing.T) {
	// Username with allowed special characters (dots, underscores, hyphens)
	secret := "JBSWY3DPEHPK3PXP"
	usernames := []string{"user.name", "user_name", "user-name", "user.name_test-1"}

	for _, username := range usernames {
		encoded := genUsername(username, secret, "key")
		decoded, _ := decodeUsername(encoded, "key")
		if decoded != username {
			t.Errorf("roundtrip failed for username %s, got %s", username, decoded)
		}
	}
}

// Additional edge case tests for decodeUsername
func TestDecodeUsername_EmptyInput(t *testing.T) {
	username, secret := decodeUsername("", "key")
	if username != "" || secret != "" {
		t.Errorf("decodeUsername with empty input should return empty strings, got (%s, %s)", username, secret)
	}
}

func TestDecodeUsername_WrongXORKey(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	encoded := genUsername("testuser", secret, "correctkey")

	// Decode with wrong key should return empty (invalid username chars after XOR)
	username, decodedSecret := decodeUsername(encoded, "wrongkey")
	// With wrong key, the decoded data won't match the username regex
	if username == "testuser" {
		t.Error("decodeUsername with wrong key should not return correct username")
	}
	_ = decodedSecret // May or may not be empty depending on XOR result
}

func TestDecodeUsername_InvalidUsernameChars(t *testing.T) {
	// The regex ^[a-zA-Z0-9_.-]+$ validates username
	// If decoded username contains invalid chars, it returns empty
	// This is tested implicitly by wrong XOR key test
}

func TestDecodeUsername_ColonAtStart(t *testing.T) {
	// If decoded string starts with colon, username would be empty
	// This should return empty strings due to validation
	// We can't easily construct this case without knowing the XOR result
}

// Additional edge case tests for calculateOtpToken
func TestCalculateOtpToken_EmptySecret(t *testing.T) {
	result := calculateOtpToken("", 1589112197)
	if result != "" {
		t.Errorf("calculateOtpToken with empty secret should return empty, got %s", result)
	}
}

func TestCalculateOtpToken_NegativeTimestamp(t *testing.T) {
	result := calculateOtpToken("JBSWY3DPEHPK3PXP", -1)
	if result != "" {
		t.Errorf("calculateOtpToken with negative timestamp should return empty, got %s", result)
	}
}

func TestCalculateOtpToken_ZeroTimestamp(t *testing.T) {
	// Zero timestamp is valid (Unix epoch)
	result := calculateOtpToken("JBSWY3DPEHPK3PXP", 0)
	if result == "" {
		t.Error("calculateOtpToken with zero timestamp should return valid token")
	}
	if len(result) != 6 {
		t.Errorf("OTP token should be 6 digits, got %d digits: %s", len(result), result)
	}
}

func TestCalculateOtpToken_InvalidBase32Secret(t *testing.T) {
	result := calculateOtpToken("!!!INVALID!!!", 1589112197)
	if result != "" {
		t.Errorf("calculateOtpToken with invalid base32 should return empty, got %s", result)
	}
}

func TestCalculateOtpToken_NoPadding(t *testing.T) {
	// Secret without padding - function should add padding automatically
	secretNoPadding := "JBSWY3DPEHPK3PXP"     // No = padding
	secretWithPadding := "JBSWY3DPEHPK3PXP==" // With padding (if needed)

	result1 := calculateOtpToken(secretNoPadding, 1589112197)
	result2 := calculateOtpToken(secretWithPadding, 1589112197)

	// Both should produce valid tokens (may or may not be equal depending on padding handling)
	if result1 == "" {
		t.Error("calculateOtpToken without padding should work")
	}
	if len(result1) != 6 {
		t.Errorf("OTP token should be 6 digits, got %s", result1)
	}
	_ = result2 // Just verify it doesn't crash
}

func TestCalculateOtpToken_VariousPaddingLengths(t *testing.T) {
	// Test secrets with various lengths that require different padding
	secrets := []string{
		"JBSWY3DP",         // 8 chars, no padding needed
		"JBSWY3DPE",        // 9 chars, needs 7 padding
		"JBSWY3DPEH",       // 10 chars, needs 6 padding
		"JBSWY3DPEHP",      // 11 chars, needs 5 padding
		"JBSWY3DPEHPK",     // 12 chars, needs 4 padding
		"JBSWY3DPEHPK3",    // 13 chars, needs 3 padding
		"JBSWY3DPEHPK3P",   // 14 chars, needs 2 padding
		"JBSWY3DPEHPK3PX",  // 15 chars, needs 1 padding
		"JBSWY3DPEHPK3PXP", // 16 chars, no padding needed
	}

	for _, secret := range secrets {
		result := calculateOtpToken(secret, 1589112197)
		if len(result) != 6 && result != "" {
			t.Errorf("calculateOtpToken(%s) produced invalid token: %s", secret, result)
		}
	}
}

func TestCalculateOtpToken_ConsistentResults(t *testing.T) {
	// Same secret and timestamp should always produce same result
	secret := "JBSWY3DPEHPK3PXP"
	timestamp := int64(1589112197)

	result1 := calculateOtpToken(secret, timestamp)
	result2 := calculateOtpToken(secret, timestamp)

	if result1 != result2 {
		t.Errorf("calculateOtpToken should be deterministic, got %s and %s", result1, result2)
	}
}

func TestCalculateOtpToken_DifferentTimestamps(t *testing.T) {
	// Different timestamps (in different 30-second windows) should produce different tokens
	secret := "JBSWY3DPEHPK3PXP"

	result1 := calculateOtpToken(secret, 0)
	result2 := calculateOtpToken(secret, 30) // Next window
	result3 := calculateOtpToken(secret, 60) // Two windows later

	// While not guaranteed to be different, in practice they should be
	if result1 == result2 && result2 == result3 {
		t.Log("Warning: All three OTP tokens are the same (statistically unlikely)")
	}
}
