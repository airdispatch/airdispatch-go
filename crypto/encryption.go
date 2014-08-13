package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
)

// Message Encryption Methods

var AESKeySize int = 256

type AESKey []byte
type EncryptedAESKey []byte

func EncryptAESKey(a AESKey, b *rsa.PublicKey) (EncryptedAESKey, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), Random, b, a, nil)
	if err != nil {
		return nil, err
	}
	return EncryptedAESKey(encryptedKey), nil
}

func EncryptDataWithRandomAESKey(plaintext []byte) (aesCipher []byte, unencryptedKey AESKey, err error) {
	var tempKey []byte

	tempKey, err = generateRandomAESKey(AESKeySize)
	if err != nil {
		return
	}
	unencryptedKey = AESKey(tempKey)

	aesCipher, err = encryptAES(plaintext, tempKey)
	if err != nil {
		return
	}

	return
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
