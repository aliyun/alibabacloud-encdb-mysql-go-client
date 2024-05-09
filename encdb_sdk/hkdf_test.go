package encdb_sdk

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSHA256HKDF(t *testing.T) {
	secret, _ := hex.DecodeString("11223344556677888877665544332211")
	salt, _ := hex.DecodeString("e8928e150bec6956")
	expected, _ := hex.DecodeString("203f64719e7930c17e6721608a65721b")
	computed := HKDF(secret, salt, nil, len(expected), SHA256)
	if !bytes.Equal(expected, computed) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(computed))
	}
}

func TestSM3HKDF(t *testing.T) {
	secret, _ := hex.DecodeString("11223344556677888877665544332211")
	salt, _ := hex.DecodeString("d66a4cf28420df31")
	expected, _ := hex.DecodeString("4d0173e4407e147a74ed9bc577a6c47b")
	computed := HKDF(secret, salt, nil, len(expected), SM3)
	if !bytes.Equal(expected, computed) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(computed))
	}
}
