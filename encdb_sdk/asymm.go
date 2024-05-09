package encdb_sdk

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func getRSAPublicKey(puk_pem string) *rsa.PublicKey {
	spkiBlock, _ := pem.Decode([]byte(puk_pem))
	puk, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPuk, isRsa := puk.(*rsa.PublicKey)
	if !isRsa {
		panic("Invalid rsa puk: " + puk_pem)
	}
	return rsaPuk
}

func getRSAPrivateKey(priv_pem string) *rsa.PrivateKey {
	spkiBlock, _ := pem.Decode([]byte(priv_pem))
	privk, err := x509.ParsePKCS8PrivateKey(spkiBlock.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPrivk, isRsa := privk.(*rsa.PrivateKey)
	if !isRsa {
		panic("Invalid rsa privk: " + priv_pem)
	}
	return rsaPrivk
}

func getSM2PublicKey(puk_pem string) *ecdsa.PublicKey {
	block, _ := pem.Decode([]byte(puk_pem))
	if block == nil {
		panic("Failed to parse PEM block")
	}
	puk, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	sm2Puk, ok := puk.(*ecdsa.PublicKey)
	if !ok {
		panic("Not expected sm2 public key")
	}
	return sm2Puk
}

func getSM2PrivateKey(priv_pem string) *sm2.PrivateKey {
	block, _ := pem.Decode([]byte(priv_pem))
	if block == nil {
		panic("Failed to parse PEM block")
	}
	privk, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	sm2Privk, ok := privk.(*sm2.PrivateKey)
	if !ok {
		panic("Not expected sm2 private key")
	}
	return sm2Privk
}

func AsymmEncrypt(puk_pem string, plaintext []byte, algo AsymmAlgo) ([]byte, error) {
	if algo == RSA {
		rsaPuk := getRSAPublicKey(puk_pem)
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPuk, plaintext, nil)
		return ciphertext, err
	} else {
		sm2Puk := getSM2PublicKey(puk_pem)
		ciphertext, err := sm2.Encrypt(rand.Reader, sm2Puk, plaintext, sm2.ASN1EncrypterOpts)
		return ciphertext, err
	}
}

func AsymmDecrypt(privk_pem string, ciphertext []byte, algo AsymmAlgo) ([]byte, error) {
	if algo == RSA {
		rsaPrivk := getRSAPrivateKey(privk_pem)
		plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, rsaPrivk, ciphertext, nil)
		return plaintext, err
	} else {
		sm2Privk := getSM2PrivateKey(privk_pem)
		plaintext, err := sm2Privk.Decrypt(rand.Reader, ciphertext, sm2.ASN1DecrypterOpts)
		return plaintext, err
	}
}
