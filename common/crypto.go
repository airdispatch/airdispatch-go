package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"code.google.com/p/go.crypto/ripemd160"
	"fmt"
	"io"
	"os"
	"encoding/gob"
	"math/big"
	"bytes"
	"encoding/hex"
	"airdispat.ch/airdispatch"
)

var EllipticCurve elliptic.Curve = elliptic.P256()
var random io.Reader = rand.Reader

func main() {
	key, err := CreateKey()
	fmt.Println(err)
	fmt.Println(key)
	signature, _ := GenerateSignature(key, []byte("hello"))
	fmt.Println(signature)
	fmt.Println(VerifySignature([]byte("hello"), signature, &key.PublicKey))
}

func padding(byteArray []byte, length int) []byte {
	if(len(byteArray) > length) {
		return nil
	} else if (len(byteArray) == length) {
		return byteArray
	}
	diff := length - len(byteArray)
	pad := make([]byte, diff)
	return bytes.Join([][]byte{pad, byteArray}, nil)
}

func CreateKey() (key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(EllipticCurve, random)
	return
}

func Sign(key *ecdsa.PrivateKey, payload []byte) (r, s *big.Int, err error) {
	r, s, err = ecdsa.Sign(random, key, payload)
	return
}

func Verify(key *ecdsa.PublicKey, payload []byte, r, s *big.Int) bool {
	return ecdsa.Verify(key, payload, r, s)
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
	x := padding(key.X.Bytes(), 32) // 32 Byte Value
	y := padding(key.Y.Bytes(), 32) // 32 Byte Value
	prefix := []byte{3} // For near-Bitcoin Compatibility
	total := bytes.Join([][]byte{prefix, x, y}, nil)
	return total
}

func BytesToKey(data []byte) *ecdsa.PublicKey {
	if len(data) != 65 {
		fmt.Println("Not Right Length")
		// Key is not the correct number of bytes
		return nil
	}
	if !bytes.Equal([]byte{3}, data[0:1]) {
		// Key does not possess the correct prefix
		return nil
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])
	key := &ecdsa.PublicKey{
		X: x,
		Y: y,
		Curve: EllipticCurve,
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

// Keygen Variables
type EncodedECDSAKey struct {
	D, X, Y *big.Int
}

func LoadKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	// Open the File for Loading
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	decodedKey := &EncodedECDSAKey{}

	// Create the decoder
	dec := gob.NewDecoder(file)
	// Load from the File
	err = dec.Decode(&decodedKey)
	if err != nil {
		return nil, err
	}

	// Reconstruct the Key
	newPublicKey := ecdsa.PublicKey{EllipticCurve, decodedKey.X, decodedKey.Y}
	newPrivateKey := ecdsa.PrivateKey{newPublicKey, decodedKey.D}

	return &newPrivateKey, nil
}

func SaveKeyToFile(filename string, key *ecdsa.PrivateKey) error {
	saveKey := EncodedECDSAKey{key.D, key.PublicKey.X, key.PublicKey.Y}

	// Create the File to Store the Keys in
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	// Create the Encoder
	enc := gob.NewEncoder(file)

	// Write to File
	err = enc.Encode(saveKey)
	if err != nil {
		return err
	}
	return nil
}
