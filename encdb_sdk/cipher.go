package encdb_sdk

import (
	"bytes"
	"encoding/hex"
	"errors"
)

// Help parse a cipher
type EncdbCipher struct {
	checkCode  []byte
	nonce      []byte
	version    uint8
	dataType   uint8
	algo       uint8
	body       []byte // Things needed for decryption, including iv and encrypted plaintext.
	data       []byte // Things taken into consideration when calculating check code.
	ciphertext []byte // Whole cipher. Including everything.
}

const (
	CHECK_CODE_SIZE = 1
	DATA_TYEP_SIZE  = 1
	BITS_SIZE       = 1
	NONCE_SIZE      = 8
	HEADER_SIZE     = CHECK_CODE_SIZE + DATA_TYEP_SIZE + BITS_SIZE
)

func xorArray(data []byte, retsize int) []byte {
	ret := make([]byte, retsize)
	for i := 0; i < len(data); i++ {
		ret[i%retsize] ^= data[i]
	}
	return ret
}

func verifyCheckCode(data []byte, expected []byte) bool {
	computed := xorArray(data, CHECK_CODE_SIZE)
	return bytes.Equal(computed, expected)
}

func (encdb_cipher *EncdbCipher) isValidCipher() bool {
	algo, _ := encdb_cipher.GetEncAlgo()
	if !verifyCheckCode(encdb_cipher.data, encdb_cipher.checkCode) {
		return false
	}
	switch algo {
	case SM4_128_CBC:
		return (len(encdb_cipher.body)-CBC_IV_SIZE)%SM4_BLOCK_SIZE == 0
	case AES_128_CBC:
		return (len(encdb_cipher.body)-CBC_IV_SIZE)%AES_BLOCK_SIZE == 0
	case SM4_128_GCM:
	case AES_128_GCM:
		return (GCM_IV_SIZE + GCM_TAG_SIZE) < len(encdb_cipher.body)
	case SM4_128_ECB:
		return len(encdb_cipher.body)%SM4_BLOCK_SIZE == 0
	case AES_128_ECB:
		return len(encdb_cipher.body)%AES_BLOCK_SIZE == 0
	case SM4_128_CTR:
	case AES_128_CTR:
		return CTR_IV_SIZE < len(encdb_cipher.body)
	default:
		return false
	}
	return true
}

func ParseCipher(ciphertext []byte) (*EncdbCipher, error) {
	if len(ciphertext) < HEADER_SIZE+NONCE_SIZE {
		return nil, errors.New("cipehr text cannot be shorter than 11 bytes")
	}
	encdbCipher := new(EncdbCipher)
	encdbCipher.ciphertext = ciphertext
	encdbCipher.checkCode = ciphertext[:CHECK_CODE_SIZE]
	encdbCipher.version = uint8(ciphertext[CHECK_CODE_SIZE])
	if encdbCipher.version == 64 {
		if len(ciphertext) < 12 {
			return nil, errors.New("cipehr text with version 64 cannot be shorter than 12 bytes")
		}
		// version 64
		// |code(1)|version(1)|type(1)|algo(1)|nonce(8)|body(x)|
		encdbCipher.dataType = uint8(ciphertext[2])
		encdbCipher.algo = uint8(ciphertext[3])
		encdbCipher.nonce = ciphertext[4:12]
		encdbCipher.body = ciphertext[12:]
		encdbCipher.data = ciphertext[1:]
	} else {
		// temporary version
		// |code(1)|type(1)|version&algo(1)|body(x)|nonce(8)|
		encdbCipher.dataType = uint8(ciphertext[1])
		encdbCipher.algo = uint8(ciphertext[2]) & 0x0f
		encdbCipher.version = uint8(ciphertext[2]) & 0xf0
		encdbCipher.nonce = ciphertext[len(ciphertext)-8:]
		encdbCipher.body = ciphertext[3 : len(ciphertext)-8]
		encdbCipher.data = ciphertext[1 : len(ciphertext)-8]
	}
	return encdbCipher, nil
}

func (encdb_cipher *EncdbCipher) Decrypt(key []byte) ([]byte, error) {
	alg, err := encdb_cipher.GetEncAlgo()
	if err != nil {
		return encdb_cipher.ciphertext, err
	}
	plaintext, err := SymmetricDecrypt(key, alg, encdb_cipher.body)
	if err != nil {
		return encdb_cipher.data, err
	}
	if len(plaintext) < CHECK_CODE_SIZE || !verifyCheckCode(plaintext[:len(plaintext)-CHECK_CODE_SIZE], plaintext[len(plaintext)-CHECK_CODE_SIZE:]) {
		return encdb_cipher.ciphertext, errors.New("Invalid plaintext checkcode in " + hex.EncodeToString(plaintext))
	}
	return plaintext[:len(plaintext)-CHECK_CODE_SIZE], err
}

func (encdb_cipher *EncdbCipher) GetType() uint8 {
	return encdb_cipher.dataType
}

func (encdb_cipher *EncdbCipher) GetEncAlgo() (SymmAlgo, error) {
	return FromInt(encdb_cipher.algo)
}
