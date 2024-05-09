package encdb_sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm4"
)

const (
	AES_BLOCK_SIZE   = 16
	AES_128_KEY_SIZE = 16
	SM4_BLOCK_SIZE   = 16
	SM4_KEY_SIZE     = 16
	GCM_TAG_SIZE     = 16
	GCM_IV_SIZE      = 12
	CBC_IV_SIZE      = 16
	CTR_IV_SIZE      = 16
)

func SymmetricKeyValid(key []byte, alg SymmAlgo) bool {
	if strings.HasPrefix(string(alg), "AES") {
		return len(key) == AES_128_KEY_SIZE
	} else if strings.HasPrefix(string(alg), "SM4") {
		return len(key) == SM4_KEY_SIZE
	} else {
		panic("Unsupported algorithm " + alg)
	}
}

func SymmetricEncrypt(key []byte, alg SymmAlgo, plaintext []byte) []byte {
	var ciphertext []byte
	switch alg {
	case SM4_128_CBC:
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		pkcs7 := padding.NewPKCS7Padding(SM4_BLOCK_SIZE)
		plaintext = pkcs7.Pad(plaintext)
		ciphertext = make([]byte, CBC_IV_SIZE+len(plaintext))
		iv := ciphertext[:CBC_IV_SIZE]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}
		sm4cbc := cipher.NewCBCEncrypter(block, iv)
		sm4cbc.CryptBlocks(ciphertext[CBC_IV_SIZE:], plaintext)
		break
	case SM4_128_GCM:
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := make([]byte, GCM_IV_SIZE)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}
		sm4gcm, err := cipher.NewGCM(block)
		ciphertext = sm4gcm.Seal(nil, iv, plaintext, nil)
		tag := ciphertext[len(ciphertext)-GCM_TAG_SIZE:]
		ciphertext = ciphertext[:len(ciphertext)-GCM_TAG_SIZE]
		ciphertext = append(append(iv[:], tag[:]...), ciphertext[:]...)
		break
	case AES_128_CBC:
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		pkcs7 := padding.NewPKCS7Padding(SM4_BLOCK_SIZE)
		plaintext = pkcs7.Pad(plaintext)
		ciphertext = make([]byte, CBC_IV_SIZE+len(plaintext))
		iv := ciphertext[:CBC_IV_SIZE]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}
		aescbc := cipher.NewCBCEncrypter(block, iv)
		aescbc.CryptBlocks(ciphertext[CBC_IV_SIZE:], plaintext)
		break
	case AES_128_GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := make([]byte, GCM_IV_SIZE)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}
		aesgcm, err := cipher.NewGCM(block)
		ciphertext = aesgcm.Seal(nil, iv, plaintext, nil)
		tag := ciphertext[len(ciphertext)-GCM_TAG_SIZE:]
		ciphertext = ciphertext[:len(ciphertext)-GCM_TAG_SIZE]
		ciphertext = append(append(iv[:], tag[:]...), ciphertext[:]...)
		break
	default:
		panic("Unsupported algo " + alg)
	}
	return ciphertext
}

func SymmetricDecrypt(key []byte, alg SymmAlgo, ciphertext []byte) ([]byte, error) {
	var plaintext []byte
	switch alg {
	case SM4_128_CBC:
		if (len(ciphertext) < CBC_IV_SIZE+SM4_BLOCK_SIZE) || (len(ciphertext)-CBC_IV_SIZE)%SM4_BLOCK_SIZE != 0 {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:CBC_IV_SIZE]
		ciphertext = ciphertext[CBC_IV_SIZE:]
		sm4cbc := cipher.NewCBCDecrypter(block, iv)
		sm4cbc.CryptBlocks(ciphertext, ciphertext)
		// Unpad plaintext
		pkcs7 := padding.NewPKCS7Padding(SM4_BLOCK_SIZE)
		plaintext, err = pkcs7.Unpad(ciphertext)
		if err != nil {
			return nil, err
		}
		break
	case AES_128_CBC:
		if (len(ciphertext) < CBC_IV_SIZE+AES_BLOCK_SIZE) || (len(ciphertext)-CBC_IV_SIZE)%AES_BLOCK_SIZE != 0 {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:CBC_IV_SIZE]
		ciphertext = ciphertext[CBC_IV_SIZE:]
		aescbc := cipher.NewCBCDecrypter(block, iv)
		aescbc.CryptBlocks(ciphertext, ciphertext)
		// Unpad plaintext
		pkcs7 := padding.NewPKCS7Padding(AES_BLOCK_SIZE)
		plaintext, err = pkcs7.Unpad(ciphertext)
		if err != nil {
			return nil, err
		}
		break
	case SM4_128_GCM:
		if len(ciphertext) < GCM_IV_SIZE+GCM_TAG_SIZE {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:GCM_IV_SIZE]
		tag := ciphertext[GCM_IV_SIZE : GCM_IV_SIZE+GCM_TAG_SIZE]
		ciphertext = ciphertext[GCM_IV_SIZE+GCM_TAG_SIZE:]
		sm4gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		plaintext, err = sm4gcm.Open(nil, iv, append(ciphertext[:], tag[:]...), nil)
		if err != nil {
			return nil, err
		}
		break
	case AES_128_GCM:
		if len(ciphertext) < GCM_IV_SIZE+GCM_TAG_SIZE {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:GCM_IV_SIZE]
		tag := ciphertext[GCM_IV_SIZE : GCM_IV_SIZE+GCM_TAG_SIZE]
		ciphertext = ciphertext[GCM_IV_SIZE+GCM_TAG_SIZE:]
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		plaintext, err = aesgcm.Open(nil, iv, append(ciphertext[:], tag[:]...), nil)
		if err != nil {
			return nil, err
		}
		break
	case SM4_128_ECB:
		if (len(ciphertext) < SM4_BLOCK_SIZE) || (len(ciphertext)%SM4_BLOCK_SIZE != 0) {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		plaintext = make([]byte, len(ciphertext))
		for bs, be := 0, SM4_BLOCK_SIZE; bs < len(ciphertext); bs, be = bs+SM4_BLOCK_SIZE, be+SM4_BLOCK_SIZE {
			block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
		}
		pkcs7 := padding.NewPKCS7Padding(SM4_BLOCK_SIZE)
		plaintext, err = pkcs7.Unpad(plaintext)
		if err != nil {
			return nil, err
		}
		break
	case AES_128_ECB:
		if (len(ciphertext) < AES_BLOCK_SIZE) || (len(ciphertext)%AES_BLOCK_SIZE != 0) {
			return ciphertext, errors.New(fmt.Sprintf("Cipher length %d invalid for algo %s ", len(ciphertext), alg))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		plaintext = make([]byte, len(ciphertext))
		for bs, be := 0, AES_BLOCK_SIZE; bs < len(ciphertext); bs, be = bs+AES_BLOCK_SIZE, be+AES_BLOCK_SIZE {
			block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
		}
		pkcs7 := padding.NewPKCS7Padding(AES_BLOCK_SIZE)
		plaintext, err = pkcs7.Unpad(plaintext)
		if err != nil {
			return nil, err
		}
		break
	case SM4_128_CTR:
		if len(ciphertext) < CTR_IV_SIZE {
			return ciphertext, errors.New("Cipher too short, invalid")
		}
		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:CTR_IV_SIZE]
		ciphertext = ciphertext[CTR_IV_SIZE:]
		stream := cipher.NewCTR(block, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
	case AES_128_CTR:
		if len(ciphertext) < CTR_IV_SIZE {
			return ciphertext, errors.New("Cipher too short, invalid")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		iv := ciphertext[:CTR_IV_SIZE]
		ciphertext = ciphertext[CTR_IV_SIZE:]
		stream := cipher.NewCTR(block, iv)
		plaintext = make([]byte, len(ciphertext))
		stream.XORKeyStream(plaintext, ciphertext)
	default:
		panic("Algo " + alg + "is not supported yet")
	}
	return plaintext, nil
}
