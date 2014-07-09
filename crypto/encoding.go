package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
)

func BytesToAddress(toHash []byte) []byte {
	address := HashRIP(HashSHA(toHash))
	checksum := generateChecksum(address)
	return bytes.Join([][]byte{address, checksum}, nil)
}

// This function writes an ECDSA Public Key to a bytestring.
// This is used to send the public key in the SignedMessage message.
func KeyToBytes(key *ecdsa.PublicKey) []byte {
	x := padding(key.X.Bytes(), 32) // 32 Byte Value
	y := padding(key.Y.Bytes(), 32) // 32 Byte Value
	total := bytes.Join([][]byte{ECDSAPrefix, x, y}, nil)
	return total
}

// This function creates an ECDSA Public KEy from a bytestring.
// This is used to send the public key in the SignedMessage message.
func BytesToKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 {
		// Key is not the correct number of bytes
		return nil, errors.New("The key is not the correct length.")
	}
	if !bytes.Equal(ECDSAPrefix, data[0:1]) {
		// Key does not possess the correct prefix
		return nil, errors.New("The key does not contain the correct prefix.")
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])
	key := &ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: EllipticCurve,
	}
	return key, nil
}

func RSAToBytes(key *rsa.PublicKey) []byte {
	exponentValue := new(bytes.Buffer)
	binary.Write(exponentValue, binary.BigEndian, int64(key.E))

	exponentLength := new(bytes.Buffer)
	binary.Write(exponentLength, binary.BigEndian, int32(8))

	modulusLength := new(bytes.Buffer)
	binary.Write(modulusLength, binary.BigEndian, int32(len(key.N.Bytes())))

	return bytes.Join([][]byte{RSAPrefix, exponentLength.Bytes(), exponentValue.Bytes(), modulusLength.Bytes(), key.N.Bytes()}, nil)
}

func BytesToRSA(data []byte) (*rsa.PublicKey, error) {
	byteBuffer := bytes.NewBuffer(data)

	actualPrefix := make([]byte, len(RSAPrefix))
	byteBuffer.Read(actualPrefix)

	if !bytes.Equal(RSAPrefix, actualPrefix) {
		return nil, errors.New("RSA Key had the wrong prefix.")
	}

	var lengthVar int32
	err := binary.Read(byteBuffer, binary.BigEndian, &lengthVar)
	if err != nil {
		return nil, err
	}

	var exponent int64
	err = binary.Read(byteBuffer, binary.BigEndian, &exponent)
	if err != nil {
		return nil, err
	}

	err = binary.Read(byteBuffer, binary.BigEndian, &lengthVar)
	if err != nil {
		return nil, err
	}

	modulus := make([]byte, lengthVar)
	byteBuffer.Read(modulus)

	newMod := new(big.Int).SetBytes(modulus)

	theKey := &rsa.PublicKey{
		N: newMod,
		E: int(exponent),
	}
	return theKey, nil
}
