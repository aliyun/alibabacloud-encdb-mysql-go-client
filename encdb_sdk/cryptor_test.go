package encdb_sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Test server cipher suite SM2_WITH_SM4_128_CBC_SM3
func TestCryptorSM2SM4CBCSM3Decrypt(t *testing.T) {
	mek, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ciphertext, _ := base64.StdEncoding.DecodeString("QAMEZIKUvzjK6/3FN2Y50rcHTjRerpC0BPYXzpqAL6n9E1bAx8hVumgv1Q==")
	data, _ := hex.DecodeString("31")
	cryptor := &Cryptor{
		Algo: SM4_128_CBC,
		MEK:  mek,
		Server_cs: CipherSuite{
			symmAlgo:  SM4_128_CBC,
			asymmAlgo: SM2,
			hashAlgo:  SM3,
		},
	}
	plaintext, _, err := cryptor.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

// Test server cipher suite SM2_WITH_SM4_128_GCM_SM3
func TestCryptorSM2SM4GCMM3Decrypt(t *testing.T) {
	mek, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ciphertext, _ := base64.StdEncoding.DecodeString("AAMHCnt0Qk8+3Cjc8V9aA0txNAcxhw+kN0uW+dLaJWWiFQeNw04N2Do=")
	data, _ := hex.DecodeString("31")
	cryptor := &Cryptor{
		Algo: SM4_128_GCM,
		MEK:  mek,
		Server_cs: CipherSuite{
			symmAlgo:  SM4_128_GCM,
			asymmAlgo: SM2,
			hashAlgo:  SM3,
		},
	}
	plaintext, _, err := cryptor.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

// Test server cipher suite RSA_WITH_AES_128_CBC_SHA256
func TestCryptorRSAAESCBCSHA256Decrypt(t *testing.T) {
	mek, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ciphertext, _ := base64.StdEncoding.DecodeString("NAMDUYqQ+9t6M8NlzKx83UfXNHb8/Dg5q6O5AGOBowwUC0E8w8bqHA44UA==")
	data, _ := hex.DecodeString("31")
	cryptor := &Cryptor{
		Algo: AES_128_CBC,
		MEK:  mek,
		Server_cs: CipherSuite{
			symmAlgo:  AES_128_CBC,
			asymmAlgo: RSA,
			hashAlgo:  SHA256,
		},
	}
	plaintext, _, err := cryptor.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

// Test server cipher suite RSA_WITH_AES_128_GCM_SHA256
func TestCryptorRSAAESGCMSHA256Decrypt(t *testing.T) {
	mek, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ciphertext, _ := base64.StdEncoding.DecodeString("OQMA6xDKnn0oSKeAKuof+gtCrGjTEjTC3TKyUq+I+7hbbVRy63VwH1c=")
	data, _ := hex.DecodeString("31")
	cryptor := &Cryptor{
		Algo: AES_128_GCM,
		MEK:  mek,
		Server_cs: CipherSuite{
			symmAlgo:  AES_128_GCM,
			asymmAlgo: RSA,
			hashAlgo:  SHA256,
		},
	}
	plaintext, _, err := cryptor.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}
