package common

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"code.google.com/p/go.crypto/ripemd160"
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"io"
	"errors"
	"math/big"
	"bytes"
	"encoding/hex"
	"airdispat.ch/airdispatch"
)

var random = rand.Reader

// The CreateADKey() function generates an ECDSA Signing key and
// an RSA keypair.
func CreateADKey() (key *ADKey, err error) {
	key = &ADKey{}

	// Create Signing Key
	key.SignatureKey, err = ecdsa.GenerateKey(ADEllipticCurve, random)
	if err != nil {
		return nil, err
	}

	key.EncryptionKey, err = rsa.GenerateKey(random, 2048)
	if err != nil {
		return nil, err
	}

	return key, err
}

// Encapsulates ECDSA Signature Generation
func signPayload(key *ecdsa.PrivateKey, payload []byte) (r, s *big.Int, err error) {
	return ecdsa.Sign(random, key, payload)
}

// Encapsulates ECDSA Signature Verification
func verifyPayload(key *ecdsa.PublicKey, payload []byte, r, s *big.Int) bool {
	return ecdsa.Verify(key, payload, r, s)
}

// Unwinds the R and S values of the ECDSA keypair from the Airdispatch Signature
// then passes them to the verifyPayload function.
func verifySignature(hash []byte, sig *airdispatch.Signature, key *ecdsa.PublicKey) bool {
	var r, s = new(big.Int), new(big.Int)
	r.SetBytes(sig.R)
	s.SetBytes(sig.S)
	return verifyPayload(key, hash, r, s)
}

// This function takes an Airdispatch SignedMessage and verifies that the signature
// was computed correctly
func VerifySignedMessage(mes *airdispatch.SignedMessage) bool {
	key, err := BytesToKey(mes.SigningKey)
	if err != nil {
		return false
	}

	hash := HashSHA(nil, mes.Payload)
	return verifySignature(hash, mes.Signature, key)
}

// This function writes an ECDSA Public Key to a bytestring.
// This is used to send the public key in the SignedMessage message.
func KeyToBytes(key *ecdsa.PublicKey) []byte {
	x := padding(key.X.Bytes(), 32) // 32 Byte Value
	y := padding(key.Y.Bytes(), 32) // 32 Byte Value
	total := bytes.Join([][]byte{_privateADECDSAPrefix, x, y}, nil)
	return total
}

// This function creates an ECDSA Public KEy from a bytestring.
// This is used to send the public key in the SignedMessage message.
func BytesToKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 {
		// Key is not the correct number of bytes
		return nil, errors.New("The key is not the correct length.")
	}
	if !bytes.Equal(_privateADECDSAPrefix, data[0:1]) {
		// Key does not possess the correct prefix
		return nil, errors.New("The key does not contain the correct prefix.")
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])
	key := &ecdsa.PublicKey{
		X: x,
		Y: y,
		Curve: ADEllipticCurve,
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

	return bytes.Join([][]byte{_privateADRSAPrefix, exponentLength.Bytes(), exponentValue.Bytes(), modulusLength.Bytes(), key.N.Bytes()}, nil)
}

func BytesToRSA(data []byte) (*rsa.PublicKey, error) {
	byteBuffer := bytes.NewBuffer(data)

	actualPrefix := make([]byte, len(_privateADRSAPrefix))
	byteBuffer.Read(actualPrefix)

	if !bytes.Equal(_privateADRSAPrefix, actualPrefix) {
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

	theKey := &rsa.PublicKey {newMod, int(exponent)}
	return theKey, nil
}

// Encapsulation for the SHA Hasher
func HashSHA(prepend []byte, payload []byte) []byte {
	hasher := sha256.New()
	hasher.Write(payload)
	return hasher.Sum(prepend)
}

// Encapsulation for the RIPEMD160 Hasher
func HashRIP(prepend []byte, payload []byte) []byte {
	hasher := ripemd160.New()
	hasher.Write(payload)
	return hasher.Sum(prepend)
}

// Quickly Generate an Address Checksum
func generateChecksum(address []byte) []byte {
	return HashSHA(nil, HashSHA(nil, address))[0:4]
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

// Creates the Base-16 String representation of the
// airdispatch key.
func (a *ADKey) HexEncode() string {
	address := a.byteAddress()
	return hex.EncodeToString(address)
}

// Creates the AD Address in Bytes
func (a *ADKey) byteAddress() []byte {
	toHash := KeyToBytes(&a.SignatureKey.PublicKey)
	address := HashRIP(nil, HashSHA(nil, toHash))
	checksum := generateChecksum(address)
	return bytes.Join([][]byte{address, checksum}, nil)
}

// Message Encryption Methods

func EncryptPayload(p []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	key, cipher, err := hybridEncryption(publicKey, p)
	if err != nil {
		return nil, err
	}

	encryptionMessage := &airdispatch.EncryptedData {
		Ciphertext: cipher,
		Key: key,
	}

	data, err := proto.Marshal(encryptionMessage)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (a *ADKey) DecryptPayload(c []byte) ([]byte, error) {
	encryptionMessage := &airdispatch.EncryptedData{}
	err := proto.Unmarshal(c, encryptionMessage)
	if err != nil {
		return nil, err
	}

	p, err := hybridDecryption(a.EncryptionKey, encryptionMessage.Key, encryptionMessage.Ciphertext)
	if err != nil {
		return nil, err
	}

	return p, nil
}

var AESKeySize int = 256

func hybridEncryption(rsaKey *rsa.PublicKey, plaintext []byte) (aesKey []byte, ciphertext []byte, error error) {
	aesKey, err := generateRandomAESKey(AESKeySize)
	if err != nil {
		return nil, nil, err
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), random, rsaKey, aesKey, nil)
	if err != nil {
		return nil, nil, err
	}

	aesCipher, err := encryptAES(plaintext, aesKey)
	if err != nil {
		return nil, nil, err
	}

	return encryptedKey, aesCipher, nil
}

func hybridDecryption(rsaKey *rsa.PrivateKey, encryptedAesKey []byte, ciphertext []byte) (plaintext []byte, error error) {
	decryptedKey, err := rsa.DecryptOAEP(sha256.New(), random, rsaKey, encryptedAesKey, nil)
	if err != nil {
		return nil, err
	}

	return decryptAES(ciphertext, decryptedKey)
}

func generateRandomAESKey(nbits int) ([]byte, error) {
	b := make([]byte, (nbits/8))
	n, err := io.ReadFull(random, b)

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
	ciphertext = make([]byte, aes.BlockSize + len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(random, iv); err != nil {
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
