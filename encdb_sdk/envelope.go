package encdb_sdk

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

/*
 * EncDB envelope format:
 * | ephemeral key length (16 bit) | ephemeral key | envelope |
 */

func EnvelopeOpen(cc CipherSuite, prik string, envelope []byte) ([]byte, error) {
	symm := cc.symmAlgo
	asymm := cc.asymmAlgo
	var tempKeyLen uint16
	err := binary.Read(bytes.NewReader(envelope), binary.LittleEndian, &tempKeyLen)
	if err != nil {
		return nil, errors.New("invalid envelope")
	}
	tempKey, err := AsymmDecrypt(prik, envelope[2:2+tempKeyLen], asymm)
	if err != nil || (len(tempKey) != AES_128_KEY_SIZE && len(tempKey) != SM4_KEY_SIZE) {
		return nil, errors.New("invalid ephemeral key in envelope")
	}
	ciphertext := envelope[2+tempKeyLen:]
	plaintext, err := SymmetricDecrypt(tempKey, symm, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func EnvelopeSeal(cc CipherSuite, puk string, data []byte) ([]byte, error) {
	symm := cc.symmAlgo
	asymm := cc.asymmAlgo
	var tempKey []byte
	var encryptedTempKeyLen uint16
	var keyLen []byte
	if strings.HasPrefix(string(symm), "AES") {
		tempKey = make([]byte, AES_128_KEY_SIZE)
	} else {
		tempKey = make([]byte, SM4_BLOCK_SIZE)
	}

	if _, err := io.ReadFull(rand.Reader, tempKey); err != nil {
		panic(err)
	}
	encryptedTempKey, err := AsymmEncrypt(puk, tempKey, asymm)
	if err != nil {
		panic(err)
	}
	encryptedTempKeyLen = uint16(len(encryptedTempKey))
	keyLen = make([]byte, 2)
	binary.LittleEndian.PutUint16(keyLen, encryptedTempKeyLen)
	encryptedData := SymmetricEncrypt(tempKey, symm, data)
	return append(append(keyLen[:], encryptedTempKey[:]...), encryptedData[:]...), err
}
