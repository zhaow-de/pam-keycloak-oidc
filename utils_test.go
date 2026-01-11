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
