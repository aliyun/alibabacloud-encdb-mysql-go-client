package encdb_sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSM4CBCDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("8223a56c5b84856e90014acfd308d04e")
	ciphertext, _ := base64.StdEncoding.DecodeString("QAMEZIKUvzjK6/3FN2Y50rcHTjRerpC0BPYXzpqAL6n9E1bAx8hVumgv1Q==")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestSM4GCMDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("29a5f13551cb0f15c1904669f1bc7c2b")
	ciphertext, _ := base64.StdEncoding.DecodeString("AAMHCnt0Qk8+3Cjc8V9aA0txNAcxhw+kN0uW+dLaJWWiFQeNw04N2Do=")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestAESCBCDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("99072be56ecf70fb0ba56a49fd6aeae0")
	ciphertext, _ := base64.StdEncoding.DecodeString("1AMDBpO4X/QBg04JX3OIL9UvjiQY3LIodQXDfeWDDvFTLDrvEbKL0Gs1bQ==")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestAESGCMDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("6163e8322d48652fe3f2ffe5e8abf73d")
	ciphertext, _ := base64.StdEncoding.DecodeString("cQMAqjRFGaYgfsL2jUiTceDX6teEkrEbh54yWlZGYl2zlkWGB5PCPBU=")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestSM4ECBDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("122df937b10c0fd4764c6c5843cc446d")
	ciphertext, _ := base64.StdEncoding.DecodeString("RgMFOnRDX1U6fCV7JIsvM8AOIhicCuDiccSE")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestAESECBDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("51031ca05f5c9dd77ac7eea4b9fd9036")
	ciphertext, _ := base64.StdEncoding.DecodeString("+wMBtGmbpxAzF3OnTgyUhHHEH7Pq1JObjkTL")
	data, _ := hex.DecodeString("31")
	cipher, err := ParseCipher(ciphertext)
	if err != nil {
		panic(err)
	}
	plaintext, err := cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(plaintext))
	}
}

func TestSymmetricKeyValid(t *testing.T) {
	key := []byte("1234567890123456")
	if !SymmetricKeyValid(key, AES_128_CBC) {
		t.Error()
	}
	key = []byte("123456789012345")
	if SymmetricKeyValid(key, AES_128_CBC) {
		t.Error()
	}
	key = []byte("1234567890123456")
	if !SymmetricKeyValid(key, SM4_128_CBC) {
		t.Error()
	}
	key = []byte("123456789012345")
	if SymmetricKeyValid(key, SM4_128_CBC) {
		t.Error()
	}
}

func TestVersion64Cipher(t *testing.T) {
	cipher, _ := base64.StdEncoding.DecodeString("vUBjB46rbQwG9rnqivZVZmvhxDHKqrt26a4hSbve/pJYvech7enfSq6IRZqO")
	key, _ := hex.DecodeString("61a43e0f449fcbe71cdbf0d63a6b2c2a")
	encdb_cipher, err := ParseCipher(cipher)
	if err != nil {
		panic(err)
	}
	plaintext, err := encdb_cipher.Decrypt(key)
	if err != nil {
		panic(err)
	}
	if len(plaintext) != 4 || plaintext[0] != 32 {
		t.Error()
	}
}
