package main

import "testing"

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
