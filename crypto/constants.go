package crypto

import (
	"crypto/elliptic"
)

var EllipticCurve elliptic.Curve = elliptic.P256()

var RSAPrefix = []byte("AD-RSA")
var ECDSAPrefix = []byte{3}

// Seperate Encryption Types
var EncryptionNone = []byte{0, 0} // "airdispat.ch/crypto/none"
var EncryptionRSA = []byte{1, 1}  // "airdispat.ch/crypto/rsa2048-aes256"

// Seperate Signing Types
var SigningECDSA = []byte{0}
