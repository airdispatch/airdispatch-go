package message

import (
	"bytes"
	"hash"
	"io"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

// DataMessage allows transfer of arbitrarily large bytestreams.
type DataMessage struct {
	h        Header
	Hash     []byte
	Length   uint64
	Key      []byte
	Type     string
	Name     string
	Filename string
	// Decryption Helpers
	verificationHash hash.Hash
}

// CreateMailFromBytes will unmarshall a mail message given its bytes and
// header.
func CreateDataMessageFromBytes(by []byte, h Header) (*DataMessage, error) {
	unmarsh := &wire.Data{}
	err := proto.Unmarshal(by, unmarsh)
	if err != nil {
		return nil, err
	}

	return &DataMessage{
		h:        h,
		Hash:     unmarsh.GetHash(),
		Length:   unmarsh.GetLength(),
		Key:      unmarsh.GetKey(),
		Type:     unmarsh.GetType(),
		Name:     unmarsh.GetName(),
		Filename: unmarsh.GetFile(),
	}, nil
}

func (m *DataMessage) TrueLength() uint64 {
	return m.Length - aes.BlockSize
}

// ToBytes will marshal a mail message to its component bytes.
func (m *DataMessage) ToBytes() []byte {
	wireFormat := &wire.Data{
		Name:   &m.Name,
		Type:   &m.Type,
		Hash:   m.Hash,
		Key:    m.Key,
		Length: &m.Length,
	}
	by, err := proto.Marshal(wireFormat)
	if err != nil {
		panic("Can't marshal mail bytes.")
	}

	return by
}

func (m *DataMessage) DecryptReader(r io.Reader) (io.Reader, error) {
	m.verificationHash = sha256.New()

	r = io.LimitReader(r, int64(m.Length))

	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(r, iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(m.Key)
	if err != nil {
		return nil, err
	}

	stream := cipher.StreamReader{
		S: cipher.NewCFBDecrypter(block, iv),
		R: r,
	}

	return io.TeeReader(stream, m.verificationHash), nil
}

func (m *DataMessage) VerifyPayload() bool {
	return bytes.Equal(m.verificationHash.Sum(nil), m.Hash)
}
