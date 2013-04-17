package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
//	"code.google.com/p/goprotobuf/proto"
	"airdispat.ch/airdispatch"
)

var curve elliptic.Curve = elliptic.P256()
var random io.Reader = rand.Reader

func main() {
	key, err := CreateKey()
	fmt.Println(err)
	fmt.Println(key)
	signature, _ := GenerateSignature(key, []byte("hello"))
	fmt.Println(signature)
	fmt.Println(VerifySignature(signature, &key.PublicKey))
}

func CreateKey() (key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(curve, random)
	return
}

func Sign(key *ecdsa.PrivateKey, payload []byte) (r, s *big.Int, err error) {
	r, s, err = ecdsa.Sign(random, key, payload)
	return
}

func Verify(key *ecdsa.PublicKey, payload []byte, r, s *big.Int) bool {
	return ecdsa.Verify(key, payload, r, s)
}

func GenerateSignature(key *ecdsa.PrivateKey, payload []byte) (*airdispatch.Signature, error) {
	r, s, err := Sign(key, payload)
	newSignature := &airdispatch.Signature {
		R: r.Bytes(),
		S: s.Bytes(),
		Hash: payload,
	}
	return newSignature, err
}

func VerifySignature(sig *airdispatch.Signature, key *ecdsa.PublicKey) bool {
	var r, s = new(big.Int), new(big.Int)
	r.SetBytes(sig.R)
	s.SetBytes(sig.S)
	return Verify(key, sig.Hash, r, s)
}
