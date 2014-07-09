package crypto

import (
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/sha256"
)

// Encapsulation for the SHA Hasher
func HashSHA(payload []byte) []byte {
	hasher := sha256.New()
	hasher.Write(payload)
	return hasher.Sum(nil)
}

// Encapsulation for the RIPEMD160 Hasher
func HashRIP(payload []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(payload)
	return hasher.Sum(nil)
}
