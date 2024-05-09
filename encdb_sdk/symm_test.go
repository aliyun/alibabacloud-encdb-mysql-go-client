package encdb_sdk

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	algos := []SymmAlgo{SM4_128_CBC, SM4_128_GCM, AES_128_CBC, AES_128_GCM}
	for _, alg := range algos {
		key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
		plaintext := []byte("abcdefg")
		ciphertext := SymmetricEncrypt(key, alg, plaintext)
		decrypted, _ := SymmetricDecrypt(key, alg, ciphertext)
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("failed Algo %s. Expected %s, got %s", alg, hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
		}
	}
}
