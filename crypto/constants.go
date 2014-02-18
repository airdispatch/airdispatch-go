package crypto

import (
	"crypto/elliptic"
)

var EllipticCurve elliptic.Curve = elliptic.P256()

var RSAPrefix = []byte("AD-RSA")
var ECDSAPrefix = []byte{3}

var EncryptionNone = "airdispat.ch/crypto/none"
var EncryptionRSA = "airdispat.ch/crypto/rsa2048-aes256"
