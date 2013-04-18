package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"code.google.com/p/go.crypto/ripemd160"
	"fmt"
	"io"
	"math/big"
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
	fmt.Println(VerifySignature([]byte("hello"), signature, &key.PublicKey))
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
	}
	return newSignature, err
}

func VerifySignature(hash []byte, sig *airdispatch.Signature, key *ecdsa.PublicKey) bool {
	var r, s = new(big.Int), new(big.Int)
	r.SetBytes(sig.R)
	s.SetBytes(sig.S)
	return Verify(key, hash, r, s)
}

func VerifySignedMessage(mes *airdispatch.SignedMessage) bool {
	key := BytesToKey(mes.SigningKey)
	hash := HashSHA(nil, mes.Payload)
	return VerifySignature(hash, mes.Signature, key)
}

func KeyToBytes(key *ecdsa.PublicKey) []byte {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	length := int16(len(x))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, length)
	total := bytes.Join([][]byte{buf.Bytes(), x, y}, nil)
	return total
}

func BytesToKey(data []byte) *ecdsa.PublicKey {
	var length int16
	binary.Read(bytes.NewBuffer(data[0:2]), binary.BigEndian, &length)
	x := new(big.Int).SetBytes(data[2:length + 2])
	y := new(big.Int).SetBytes(data[length + 2:])
	key := &ecdsa.PublicKey{
		X: x,
		Y: y,
		Curve: curve,
	}
	return key
}

func HashSHA(prepend []byte, payload []byte) []byte {
	hasher := sha256.New()
	hasher.Write(payload)
	return hasher.Sum(prepend)
}

func HashRIP(prepend []byte, payload []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(payload)
	return hasher.Sum(prepend)
}

func GenerateChecksum(address []byte) []byte {
	return HashSHA(nil, HashSHA(nil, address))[0:4]
}

func StringAddress(key *ecdsa.PublicKey) string {
	address := AddressFromKey(key)
	return hex.EncodeToString(address)
}

func VerifyStringAddress(address string) bool {
	byteAddress, _ := hex.DecodeString(address)
	return VerifyAddress(byteAddress)
}

func AddressFromKey(key *ecdsa.PublicKey) []byte {
	toHash := KeyToBytes(key)
	address := HashRIP(nil, HashSHA(nil, toHash))
	checksum := GenerateChecksum(address)
	return bytes.Join([][]byte{address, checksum}, nil)
}

func VerifyAddress(address []byte) bool {
	location := len(address) - 4
	checksum := address[location:]
	rest := address[:location]
	return bytes.Equal(GenerateChecksum(rest), checksum)
}
