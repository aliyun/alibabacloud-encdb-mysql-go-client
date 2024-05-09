package encdb_sdk

import (
	"bytes"
	"fmt"
	"strings"
)

type AsymmAlgo string
type SymmAlgo string
type HashAlgo string

const (
	SM2 AsymmAlgo = "SM2"
	RSA           = "RSA"
)

const (
	SHA256 HashAlgo = "SHA256"
	SM3             = "SM3"
)

const (
	AES_128_CBC SymmAlgo = "AES_128_CBC"
	AES_128_CTR          = "AES_128_CTR"
	AES_128_ECB          = "AES_128_ECB"
	AES_128_GCM          = "AES_128_GCM"
	SM4_128_CBC          = "SM4_128_CBC"
	SM4_128_CTR          = "SM4_128_CTR"
	SM4_128_ECB          = "SM4_128_ECB"
	SM4_128_GCM          = "SM4_128_GCM"
	INVALID              = "INVALID"
)

type CipherSuite struct {
	asymmAlgo AsymmAlgo
	hashAlgo  HashAlgo
	symmAlgo  SymmAlgo
}

func (cs *CipherSuite) ToString() string {
	return string(cs.asymmAlgo) + "_WITH_" + string(cs.symmAlgo) + "_" + string(cs.hashAlgo)
}

func FromString(s string) *CipherSuite {
	if s == "RSA_WITH_AES_128_CBC_SHA256" {
		return &CipherSuite{
			asymmAlgo: RSA,
			symmAlgo:  AES_128_CBC,
			hashAlgo:  SHA256,
		}
	} else if s == "RSA_WITH_AES_128_GCM_SHA256" {
		return &CipherSuite{
			asymmAlgo: RSA,
			symmAlgo:  AES_128_GCM,
			hashAlgo:  SHA256,
		}
	} else if s == "SM2_WITH_SM4_128_CBC_SM3" {
		return &CipherSuite{
			asymmAlgo: SM2,
			symmAlgo:  SM4_128_CBC,
			hashAlgo:  SM3,
		}
	} else if s == "SM2_WITH_SM4_128_GCM_SM3" {
		return &CipherSuite{
			asymmAlgo: SM2,
			symmAlgo:  SM4_128_GCM,
			hashAlgo:  SM3,
		}
	} else {
		panic("Unsuppoted cipher suite " + s)
	}
}

func FromInt(i uint8) (SymmAlgo, error) {
	switch i {
	case 0:
		return AES_128_GCM, nil
	case 1:
		return AES_128_ECB, nil
	case 2:
		return AES_128_CTR, nil
	case 3:
		return AES_128_CBC, nil
	case 4:
		return SM4_128_CBC, nil
	case 5:
		return SM4_128_ECB, nil
	case 6:
		return SM4_128_CTR, nil
	case 7:
		return SM4_128_GCM, nil
	default:
		return INVALID, fmt.Errorf("%s %d", "Invalid algo number ", i)
	}
}

type Cryptor struct {
	Algo            SymmAlgo
	MEK             []byte
	Nonce           []byte
	DEK             []byte
	Server_cs       CipherSuite
	Server_puk      string // pem format
	Server_puk_hash string
}

// func (cryptor *Cryptor) encrypt(plaintext []byte) []byte {

// }

func (cryptor *Cryptor) Decrypt(ciphertext []byte) ([]byte, uint8, error) {
	encdb_cipher, err := ParseCipher(ciphertext)
	if err != nil {
		return ciphertext, 0, err
	}
	algo, err := encdb_cipher.GetEncAlgo()
	if err != nil {
		return ciphertext, 0, err
	}
	mysql_type := encdb_cipher.GetType()
	if err != nil {
		return ciphertext, mysql_type, err
	}
	if cryptor.Nonce == nil || !bytes.Equal(cryptor.Nonce, encdb_cipher.nonce) {
		// init dek and nonce for this cryptor
		cryptor.Nonce = encdb_cipher.nonce
		if strings.HasPrefix(string(algo), "AES") {
			cryptor.DEK = HKDF(cryptor.MEK, cryptor.Nonce, nil, AES_128_KEY_SIZE, cryptor.Server_cs.hashAlgo)
		} else if strings.HasPrefix(string(algo), "SM4") {
			cryptor.DEK = HKDF(cryptor.MEK, cryptor.Nonce, nil, SM4_KEY_SIZE, cryptor.Server_cs.hashAlgo)
		} else {
			panic("Unsupported algo " + algo)
		}
	}
	plaintext, err := encdb_cipher.Decrypt(cryptor.DEK)
	if err != nil {
		return ciphertext, mysql_type, err
	}
	return plaintext, mysql_type, nil
}
