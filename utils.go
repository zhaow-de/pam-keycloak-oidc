package main

import (
	"encoding/ascii85"
	"encoding/base32"
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
