package encdb_sdk

import (
	"crypto/sha256"
	"hash"
	"io"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/hkdf"
)

func HKDF(secret []byte, salt []byte, info []byte, target_size int, alg HashAlgo) []byte {
	var hash func() hash.Hash
	if alg == SM3 {
		hash = sm3.New
	} else if alg == SHA256 {
		hash = sha256.New
	} else {
		panic("Hash alg not supported: " + alg)
	}
	hkdf := hkdf.New(hash, secret, salt, info)
	ret := make([]byte, target_size)
	if _, err := io.ReadFull(hkdf, ret); err != nil {
		panic(err)
	}
	return ret
}
