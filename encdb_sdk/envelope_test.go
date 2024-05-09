package encdb_sdk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestEnvelopeOpenSM2(t *testing.T) {
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgQ5RHYzX/OFjfBM9s\np3V4dRXN34VC1wuAxHIODBxklL6hRANCAATA4MaS+FhxPFOhGbAqEFZ6/4yy7mix\nipETSqbwYwb5LVWnLx2nq0pXxgGRkh8dVsAUStN4hh87Ju1LNH+Isyfu\n-----END PRIVATE KEY-----"
	envelope, err := base64.StdEncoding.DecodeString("egAweAIgRYDXZrq2qPBqyOshLuoGyyay6xs/y+v6n4HzMG1d6JQCIAzOfuFoM6780ecyEnkLgRtsLFE21pL1ioe0Clk0KKCEBCA2joyQ7ebXxvRl0JTnjlKQcr1sSVKU+QeYrYGukFjJBQQQ0M39cLWNFcvBVegd0cmoEP6ZK26i/M8G74APaAca0ck4c7HZQKEhSUHp4k1XU4+frLaGcKZRSDlkD1+rNFzEZN8HatekwWCD3pJwBYSy5w4AO4QbxrR8JF2RK58rkrIx")
	if err != nil {
		panic(err)
	}
	cc := CipherSuite{
		asymmAlgo: SM2,
		symmAlgo:  SM4_128_CBC,
		hashAlgo:  SM3,
	}
	data, err := EnvelopeOpen(cc, priv_pem, envelope)
	if err != nil {
		panic(err)
	}
	t.Log(string(data))
}

func TestEnvelopeSealAndOpenSM2(t *testing.T) {
	Server_css := []CipherSuite{CipherSuite{symmAlgo: SM4_128_CBC, asymmAlgo: SM2, hashAlgo: SM3}, CipherSuite{symmAlgo: SM4_128_GCM, asymmAlgo: SM2, hashAlgo: SM3}}
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEwODGkvhYcTxToRmwKhBWev+Msu5o\nsYqRE0qm8GMG+S1Vpy8dp6tKV8YBkZIfHVbAFErTeIYfOybtSzR/iLMn7g==\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgQ5RHYzX/OFjfBM9s\np3V4dRXN34VC1wuAxHIODBxklL6hRANCAATA4MaS+FhxPFOhGbAqEFZ6/4yy7mix\nipETSqbwYwb5LVWnLx2nq0pXxgGRkh8dVsAUStN4hh87Ju1LNH+Isyfu\n-----END PRIVATE KEY-----"
	for _, cc := range Server_css {
		data := []byte("abcdefghi")
		envelope, err := EnvelopeSeal(cc, puk_pem, data)
		if err != nil {
			panic(err)
		}
		opened_data, err := EnvelopeOpen(cc, priv_pem, envelope)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(data, opened_data) {
			t.Errorf("Error with cc %s. Expected %s, got %s", cc.ToString(), hex.EncodeToString(data), hex.EncodeToString(opened_data))
		}
	}
}

func TestEnvelopeSealAndOpenAES(t *testing.T) {
	Server_css := []CipherSuite{CipherSuite{symmAlgo: AES_128_CBC, asymmAlgo: RSA, hashAlgo: SHA256}, CipherSuite{symmAlgo: AES_128_GCM, asymmAlgo: RSA, hashAlgo: SHA256}}
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0tX7wkiKH8HcP6bqas5e\nIqYoT36d4ebSZbSuHgQ/G260/AIhAv+OzbTwmV7YZ7d6T7aIhr5XHRyGCBfb9mZr\nl+aomnwDsNP9J4rZ82uJMDFdEv61l0dcbw3lFqOxOdNf9BLLc1ST4v51PrXoXKXh\no+yr+1AuXKdfi2xfPxGy8Zs/fXOzhwURBY/g/TI6k3UPr+RO89nUXegbYigPxeBN\nhvXah63gVUl6ozTwwpDGi3nocb6TIUETMXKbMPNhtG7WR3QwdQ7+lqiZKAXHT48w\nydq4ZvMxji9/VLEVNH1Vgn8ZegdnKDZCee1DpdrJ4D0WN2ZhO08TfkKQ8BL+C4PB\nVBpuOoQi75g5pUD0dS7OPWnW3p4tw3ThtahNA00na8tIYt5Lfe/BhDHXAPYYvOUn\nWd2JitBrn93gxuoAl6kmPtAaBIQVRlIfBtve1oZmc/GrdFhwYYwwZRvXhVsHx356\nexyHb1tBxYTbK4Us7DZNTuS4R6fMt4jXRCA1JfBKwXWrAgMBAAE=\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\n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\nG9Qx3auxMdmJaNqt12ATKU4=\n-----END PRIVATE KEY-----"
	for _, cc := range Server_css {
		data := []byte("abcdefghi")
		envelope, err := EnvelopeSeal(cc, puk_pem, data)
		if err != nil {
			panic(err)
		}
		opened_data, err := EnvelopeOpen(cc, priv_pem, envelope)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(data, opened_data) {
			t.Errorf("Error with cc %s. Expected %s, got %s", cc.ToString(), hex.EncodeToString(data), hex.EncodeToString(opened_data))
		}
	}
}
