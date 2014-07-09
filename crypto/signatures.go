package crypto

import (
	"crypto/ecdsa"
	"math/big"
)

// Encapsulates ECDSA Signature Generation
func SignPayload(key *ecdsa.PrivateKey, payload []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(Random, key, payload)
}

// Encapsulates ECDSA Signature Verification
func VerifyPayload(key *ecdsa.PublicKey, payload []byte, r, s *big.Int) bool {
	return ecdsa.Verify(key, payload, r, s)
}
