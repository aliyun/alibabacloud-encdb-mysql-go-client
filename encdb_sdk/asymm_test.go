package encdb_sdk

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestImportRSAKey(t *testing.T) {
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0tX7wkiKH8HcP6bqas5e\nIqYoT36d4ebSZbSuHgQ/G260/AIhAv+OzbTwmV7YZ7d6T7aIhr5XHRyGCBfb9mZr\nl+aomnwDsNP9J4rZ82uJMDFdEv61l0dcbw3lFqOxOdNf9BLLc1ST4v51PrXoXKXh\no+yr+1AuXKdfi2xfPxGy8Zs/fXOzhwURBY/g/TI6k3UPr+RO89nUXegbYigPxeBN\nhvXah63gVUl6ozTwwpDGi3nocb6TIUETMXKbMPNhtG7WR3QwdQ7+lqiZKAXHT48w\nydq4ZvMxji9/VLEVNH1Vgn8ZegdnKDZCee1DpdrJ4D0WN2ZhO08TfkKQ8BL+C4PB\nVBpuOoQi75g5pUD0dS7OPWnW3p4tw3ThtahNA00na8tIYt5Lfe/BhDHXAPYYvOUn\nWd2JitBrn93gxuoAl6kmPtAaBIQVRlIfBtve1oZmc/GrdFhwYYwwZRvXhVsHx356\nexyHb1tBxYTbK4Us7DZNTuS4R6fMt4jXRCA1JfBKwXWrAgMBAAE=\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\n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\nG9Qx3auxMdmJaNqt12ATKU4=\n-----END PRIVATE KEY-----"
	_ = getRSAPublicKey(puk_pem)
	_ = getRSAPrivateKey(priv_pem)
}

func TestRSAEncryptAndDecrypt(t *testing.T) {
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0tX7wkiKH8HcP6bqas5e\nIqYoT36d4ebSZbSuHgQ/G260/AIhAv+OzbTwmV7YZ7d6T7aIhr5XHRyGCBfb9mZr\nl+aomnwDsNP9J4rZ82uJMDFdEv61l0dcbw3lFqOxOdNf9BLLc1ST4v51PrXoXKXh\no+yr+1AuXKdfi2xfPxGy8Zs/fXOzhwURBY/g/TI6k3UPr+RO89nUXegbYigPxeBN\nhvXah63gVUl6ozTwwpDGi3nocb6TIUETMXKbMPNhtG7WR3QwdQ7+lqiZKAXHT48w\nydq4ZvMxji9/VLEVNH1Vgn8ZegdnKDZCee1DpdrJ4D0WN2ZhO08TfkKQ8BL+C4PB\nVBpuOoQi75g5pUD0dS7OPWnW3p4tw3ThtahNA00na8tIYt5Lfe/BhDHXAPYYvOUn\nWd2JitBrn93gxuoAl6kmPtAaBIQVRlIfBtve1oZmc/GrdFhwYYwwZRvXhVsHx356\nexyHb1tBxYTbK4Us7DZNTuS4R6fMt4jXRCA1JfBKwXWrAgMBAAE=\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\n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\nG9Qx3auxMdmJaNqt12ATKU4=\n-----END PRIVATE KEY-----"
	plaintext := []byte("12345")
	ciphertext, err := AsymmEncrypt(puk_pem, plaintext, RSA)
	if err != nil {
		panic(err)
	}
	decrypted_cipher, err := AsymmDecrypt(priv_pem, ciphertext, RSA)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, decrypted_cipher) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(plaintext), hex.EncodeToString(decrypted_cipher))
	}
}

func TestRSADecrypt(t *testing.T) {
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQDS1fvCSIofwdw/\npupqzl4ipihPfp3h5tJltK4eBD8bbrT8AiEC/47NtPCZXthnt3pPtoiGvlcdHIYI\nF9v2ZmuX5qiafAOw0/0nitnza4kwMV0S/rWXR1xvDeUWo7E501/0EstzVJPi/nU+\ntehcpeGj7Kv7UC5cp1+LbF8/EbLxmz99c7OHBREFj+D9MjqTdQ+v5E7z2dRd6Bti\nKA/F4E2G9dqHreBVSXqjNPDCkMaLeehxvpMhQRMxcpsw82G0btZHdDB1Dv6WqJko\nBcdPjzDJ2rhm8zGOL39UsRU0fVWCfxl6B2coNkJ57UOl2sngPRY3ZmE7TxN+QpDw\nEv4Lg8FUGm46hCLvmDmlQPR1Ls49adbeni3DdOG1qE0DTSdry0hi3kt978GEMdcA\n9hi85SdZ3YmK0Guf3eDG6gCXqSY+0BoEhBVGUh8G297WhmZz8at0WHBhjDBlG9eF\nWwfHfnp7HIdvW0HFhNsrhSzsNk1O5LhHp8y3iNdEIDUl8ErBdasCAwEAAQKCAYBG\nvjIZgImIGl4ypWkmqVQAwEvqUIvdTrvuEHAT9kzOgZkMrhIxlVpvP3UzoRVvx6qs\nsIyi2Z8VT4rRkF/oD3muoGCWZWI/pQHekMKM4NpJZ2bZhsmblwA26yyhKg+/XWNm\n3B+T9R8iHUtt3U+4Npi9jh4u1zqXMDno6FYVLXUjiHoHOBlXBqYtfZd6na316GN5\nG1w6ii6ty8HUb6jLNnYNANVwjTEmrN8PgCYAwt870Y3jDJUFpXYxM0lLZX61MjLr\nlCTBRO+2cLBCWB2pDHDlCJfegxyYDulkkV19A6vXsaQskx2X5R/ZhaMNvJAKU8IZ\ntvjnSUEtEt4LQbuJATnYKfm3Tw+PShUvYHaLhEHlq141hLZ+6+lvm9gqk0axp6ph\n6UkXWua90JKsBf/O6+7SZVwUuOzWEs81OQt3hJg1qbQrFvX8WLfS2svWPdGR5Bn4\n8+JGD0Y1lHxAeTpqRPxe1th1nIAdajT9oWxZ7VRPhwT9dfIiKLF5SlCI2z9v9PEC\ngcEA/MpEqhCxdq6PTTSS8e9mSvdoG4nfe1wXt94VCj8ZNPis09cKdwQolEBaPT3J\nSQeo5SPngCzj4AEfFyG/j2Ouq6puJoPNT/zTeWg39JtTwY8QvA0RI8uFcqVXfd1n\n8BQ6fpQIaXgTlkUiyA3TCe9309vWb7f1kMlHEy8DeO3oxbbQxBnfliJcRiPVygzc\nqx66O/QcRmEFuymL2WX8jufsTfqSYGWGr0QyyD5ht5FkdvsDyQJp8r71SPVITtIJ\nb4ldAoHBANWDVjRam7Cnj5UCbOhGbikAdC9AHpqSwN0TzCVLJdeCDHabKSGTbam6\nFVn+7zv2uFimbG7m8qidwAIQM6BSbL+JYWkjqx2e1upU3E63mQJTAqlL79qoH0nR\nk+mnhR/bs6aL7r2HF4LIZk80dQvtofIKAZfKDFFZUVxGfougcbfBUuG1YQbK01vZ\nLsdlrgRFJgO6Cx0VRvdm5n6bfGI/uXZGT4g1TCSXYiTZYr2xhr2oOfL1ZFnKy4lE\np76+OzqipwKBwQCPD2VWnYXhNZ7RwZwboTFR4bwgQaGhLZgarWtY1ibMzKL6bCt2\n+XqBk/29xNbCJryVmQEtj7oSjm/q5mWDn5U9f4FA+LxbtSh0/98S5ki7NNzyn66A\nhHBsVlgyWfe1ba1A70PndFYZZ9zsPK6fY897rWEo7oHhw5ceqy+a44ElS3XQVRgs\n3hs8cpFN/INxsD0TKu5JgiT9K+ECUm5g7a3U36axOSPE0qKuomcovPaPQzV8L4qI\nHzuvY2jdeo5ued0CgcBRYDcwyP/huls8/amodX9y3RtrDtMbMqeTGwKJjDSmCIjb\ng5OPmnMHZ0bQABwKDKSCFRvqwNbncQhHQQmMJx4PejrIKbIEHg/nS+STk+IbQqwW\n/jwyaDVUmy32tcRFOiUkatzZG23YiKyFr4aUv0MjzrCAu58qOhKKSsvcR5BP6ry+\nDbUnM5KOxR3RHW3PbtNoRDYMJZngnTVoN7aWc5cp/u49CaM1pwTe6oN5rPmfu0gq\n02Al4ObmMGaGilZkqK0CgcBaiCZ39Fe1sAAO5a7q8CXyhAJo+imWBeIdHlLgRKT+\n445Y4cJlcY0ECYp0+Y/s0P+n77LcsK3L63oDSn9oQZte8xNftLP6Yig8wzsPRGFM\ny97vP8nw0P2wa5ywyDL6FYKr+5S2TtSi1BYhpYFku0k0s45+WRqdfLuPtvbM19qA\nwOvI3k6JXPTnoOt42gpEG6nNp2IkER/a+gXCjXl5xBrohivq/M4Q9uD3WytU3Cxg\nG9Qx3auxMdmJaNqt12ATKU4=\n-----END PRIVATE KEY-----"
	ciphertext, _ := hex.DecodeString("39fa0b68abb30a95ba47d3d480106ecbf80193d1ad85eb92aa25b32020de62367408313e2f74866e36384da0f6087dc5bfff1a807a0e5e0a20e964ce72b119d186f15740186187ccfa429c92dbe8a8d9c6682f3283be1eb328e537e65e4364526bc8ac81fd08bfce9042fed31156bf38daca282e3f5e3acbc3cc8124533e0019988a767be45a52c4a175a9e37736b9d2051ae25c875be0742debca4e1ca0c04b27b55c4e8cf0c7b029ff2003f5fb7cf357d0015e01c6781f4ad5c340bb0f14afd9e0b8f5f99fbb9214b80718d0f7960369d2a82cf9216636335e70993f578faa33fd3b99c5e22bc2246f2027d0620a0b13a8c415bd72deb0106311351953a1e69c47236aaeaf9cf51ee0e405113bc69add180f625bd399d22c0665811b0fec2560ba4828450c92c0d6895eef1c9fd26f26031ba2094d1b5c17a578983fa48da47a61e43d4366d116a30c4b5f2cbd7fc570079c602fa9f9a7b928b14d70f701bf83280fb3a0f82522cc8d3d11067d92690db73efc0db5d4cb4d68b9911800f4d7")
	expected, _ := hex.DecodeString("1ab3c5c96628087d4958fa790ad75b6d")
	plaintext, err := AsymmDecrypt(priv_pem, ciphertext, RSA)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expected, plaintext) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(plaintext))
	}
}

func TestImportSM2Key(t *testing.T) {
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEwODGkvhYcTxToRmwKhBWev+Msu5o\nsYqRE0qm8GMG+S1Vpy8dp6tKV8YBkZIfHVbAFErTeIYfOybtSzR/iLMn7g==\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgQ5RHYzX/OFjfBM9s\np3V4dRXN34VC1wuAxHIODBxklL6hRANCAATA4MaS+FhxPFOhGbAqEFZ6/4yy7mix\nipETSqbwYwb5LVWnLx2nq0pXxgGRkh8dVsAUStN4hh87Ju1LNH+Isyfu\n-----END PRIVATE KEY-----"
	_ = getSM2PublicKey(puk_pem)
	_ = getSM2PrivateKey(priv_pem)
}

func TestSM2EncryptAndDecrypt(t *testing.T) {
	puk_pem := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEwODGkvhYcTxToRmwKhBWev+Msu5o\nsYqRE0qm8GMG+S1Vpy8dp6tKV8YBkZIfHVbAFErTeIYfOybtSzR/iLMn7g==\n-----END PUBLIC KEY-----"
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgQ5RHYzX/OFjfBM9s\np3V4dRXN34VC1wuAxHIODBxklL6hRANCAATA4MaS+FhxPFOhGbAqEFZ6/4yy7mix\nipETSqbwYwb5LVWnLx2nq0pXxgGRkh8dVsAUStN4hh87Ju1LNH+Isyfu\n-----END PRIVATE KEY-----"
	plaintext := []byte("12345")
	ciphertext, err := AsymmEncrypt(puk_pem, plaintext, SM2)
	if err != nil {
		panic(err)
	}
	decrypted_cipher, err := AsymmDecrypt(priv_pem, ciphertext, SM2)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(plaintext, decrypted_cipher) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(plaintext), hex.EncodeToString(decrypted_cipher))
	}

}

func TestSM2Decrypt(t *testing.T) {
	priv_pem := "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgQ5RHYzX/OFjfBM9s\np3V4dRXN34VC1wuAxHIODBxklL6hRANCAATA4MaS+FhxPFOhGbAqEFZ6/4yy7mix\nipETSqbwYwb5LVWnLx2nq0pXxgGRkh8dVsAUStN4hh87Ju1LNH+Isyfu\n-----END PRIVATE KEY-----"
	ciphertext, _ := hex.DecodeString("307802204580d766bab6a8f06ac8eb212eea06cb26b2eb1b3fcbebfa9f81f3306d5de89402200cce7ee16833aefcd1e73212790b811b6c2c5136d692f58a87b40a593428a0840420368e8c90ede6d7c6f465d094e78e529072bd6c495294f90798ad81ae9058c9050410d0cdfd70b58d15cbc155e81dd1c9a810")
	expected, _ := hex.DecodeString("5556dbc056ac85ec514db6fca56deda1")
	plaintext, err := AsymmDecrypt(priv_pem, ciphertext, SM2)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(expected, plaintext) {
		t.Errorf("Expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(plaintext))
	}
}