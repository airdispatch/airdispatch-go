package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
)

var Random = rand.Reader

// Encapsulates ECDSA Signature Generation
func SignPayload(key *ecdsa.PrivateKey, payload []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(Random, key, payload)
}

// Encapsulates ECDSA Signature Verification
func VerifyPayload(key *ecdsa.PublicKey, payload []byte, r, s *big.Int) bool {
	return ecdsa.Verify(key, payload, r, s)
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

	theKey := &rsa.PublicKey{newMod, int(exponent)}
	return theKey, nil
}

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

// Quickly Generate an Address Checksum
func generateChecksum(address []byte) []byte {
	return HashSHA(HashSHA(address))[0:4]
}

// Hex decode an Address then verify that it is correct, then
// pass it to the byte verification function
func VerifyStringAddress(address string) bool {
	byteAddress, err := hex.DecodeString(string(address))
	if err != nil {
		return false
	}

	return verifyAddress(byteAddress)
}

// Verify an Airdispatch Address from Bytes by comparing the checksum
// to the one provided
func verifyAddress(address []byte) bool {
	location := len(address) - 4
	checksum := address[location:]
	rest := address[:location]
	return bytes.Equal(generateChecksum(rest), checksum)
}

func BytesToAddress(toHash []byte) []byte {
	address := HashRIP(HashSHA(toHash))
	checksum := generateChecksum(address)
	return bytes.Join([][]byte{address, checksum}, nil)
}

// Message Encryption Methods

var AESKeySize int = 256

func HybridEncryption(rsaKey *rsa.PublicKey, plaintext []byte) (aesKey []byte, ciphertext []byte, error error) {
	aesKey, err := generateRandomAESKey(AESKeySize)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), Random, rsaKey, aesKey, nil)
	if err != nil {
		return nil, nil, err
	}

	aesCipher, err := encryptAES(plaintext, aesKey)
	if err != nil {
		return nil, nil, err
	}

	return encryptedKey, aesCipher, nil
}

func HybridDecryption(rsaKey *rsa.PrivateKey, encryptedAesKey []byte, ciphertext []byte) (plaintext []byte, error error) {
	decryptedKey, err := rsa.DecryptOAEP(sha256.New(), Random, rsaKey, encryptedAesKey, nil)
	if err != nil {
		return nil, err
	}

	return decryptAES(ciphertext, decryptedKey)
}

func generateRandomAESKey(nbits int) ([]byte, error) {
	b := make([]byte, (nbits / 8))
	n, err := io.ReadFull(Random, b)

	if n != len(b) || err != nil {
		return nil, err
	}

	return b, nil
}

func encryptAES(plaintext []byte, key []byte) (ciphertext []byte, error error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create IV
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(Random, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decryptAES(ciphertext []byte, key []byte) (plaintext []byte, error error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext was too short.")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// This function pads a bytestring to the correct length
// assuming that the bytestring is in big-endian format
//
// THIS FUNCTION HAS NOTHING TO DO WITH AES. IT IS ONLY USED FOR
// STORAGE OF SIGNING KEYS.
func padding(byteArray []byte, length int) []byte {
	if len(byteArray) > length {
		return nil
	} else if len(byteArray) == length {
		return byteArray
	}
	diff := length - len(byteArray)
	pad := make([]byte, diff)
	return bytes.Join([][]byte{pad, byteArray}, nil)
}
