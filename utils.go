package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/ascii85"
	"encoding/base32"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// encryptDecrypt runs XOR encryption on the input string, encrypting it if it hasn't already been,
// and decrypting it if it has, using the key provided.
func encryptDecrypt(input []byte, key string) (output []byte) {
	kL := len(key)
	for i := range input {
		output = append(output, input[i]^key[i%kL])
	}
	return output
}

func a85Encode(input []byte) (output string) {
	result := make([]byte, ascii85.MaxEncodedLen(len(input)))
	n := ascii85.Encode(result, input)
	result = result[0:n]
	output = string(result)
	return output
}

func a85Decode(input string) (output []byte) {
	dBuf := make([]byte, 4*len(input))
	if dLen, _, err := ascii85.Decode(dBuf, []byte(input), true); err == nil {
		return dBuf[0:dLen]
	}
	return nil
}

func b32decode(input string) (output []byte) {
	b32decoded, _ := base32.StdEncoding.DecodeString(strings.ToUpper(input))
	return b32decoded
}

func b32encode(input []byte) (output string) {
	return base32.StdEncoding.EncodeToString(input)
}

func genUsername(username, secret string, xorKey string) (output string) {
	usernamePart := []byte(username + ":")
	secretPart := b32decode(secret)
	if len(secretPart) == 0 {
		panic("\"" + secret + "\" does not look like an OTP secret")
	}
	return a85Encode(encryptDecrypt(append(usernamePart, secretPart...), xorKey))
}

func decodeUsername(encodedUsername string, xorKey string) (username, secret string) {
	input := encryptDecrypt(a85Decode(encodedUsername), xorKey)
	var decodedSecret []byte

	var rxUsername = regexp.MustCompile("^[a-zA-Z0-9_.-]+$")

	for r := 0; r < len(input); r++ {
		c := input[r]
		if c == ':' {
			username = string(input[0:r])
			decodedSecret = input[r+1:]
			break
		}
	}
	if username == "" || len(decodedSecret) == 0 || !rxUsername.MatchString(username) {
		return "", ""
	}
	secret = b32encode(decodedSecret)
	return username, secret
}

func calculateOtpToken(secret string, timestamp int64) string {
	if len(secret) <= 0 || timestamp < 0 {
		return ""
	}
	input := timestamp / interval
	//
	// add the missing padding if needed, then decode the secret
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secret = secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return ""
	}
	// start hashing
	sha1Hash := hmac.New(sha1.New, bytes)
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(input & 0xff)
		input = input >> 8
	}
	sha1Hash.Write(byteArr)
	hmacHash := sha1Hash.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := (((int(hmacHash[offset]) & 0x7f) << 24) | ((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) | (int(hmacHash[offset+3]) & 0xff)) % int(math.Pow10(digits))

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}
