package message

import (
	"airdispat.ch/identity"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
	"time"
)

type Mail struct {
	h          Header
	Components ComponentList
}

func CreateMail(from *identity.Address, to *identity.Address) *Mail {
	return &Mail{
		h: Header{
			From:      from,
			To:        to,
			Timestamp: time.Now().Unix(),
		},
		Components: make(ComponentList, 0),
	}
}

func CreateMailFromBytes(by []byte, h Header) (*Mail, error) {
	unmarsh := &wire.Mail{}
	err := proto.Unmarshal(by, unmarsh)
	if err != nil {
		return nil, err
	}

	c := unmarsh.GetComponents()
	comp := make(map[string]Component)
	for _, v := range c {
		comp[v.GetType()] = CreateComponent(v.GetType(), v.GetData())
	}

	return &Mail{
		h:          h,
		Components: comp,
	}, nil
}

func (m *Mail) ToBytes() []byte {
	wireFormat := &wire.Mail{
		Components: m.Components.ToWire(),
	}
	by, err := proto.Marshal(wireFormat)
	if err != nil {
		panic("Can't marshal mail bytes.")
	}

	return by
}

func (m *Mail) Type() string {
	return wire.MailCode
}

func (m *Mail) Header() Header {
	return m.h
}

type ComponentList map[string]Component

func (c ComponentList) ToWire() []*wire.Mail_Component {
	output := make([]*wire.Mail_Component, len(c))
	i := 0
	for _, v := range c {
		output[i] = &wire.Mail_Component{
			Type: &v.Name,
			Data: v.Data,
		}
		i += 1
	}
	return output
}

func (c ComponentList) AddComponent(comp Component) {
	c[comp.Name] = comp
}

func (c ComponentList) HasComponent(name string) bool {
	_, ok := c[name]
	return ok
}

func (c ComponentList) GetComponent(name string) []byte {
	b, _ := c[name]
	return b.Data
}

func (c ComponentList) GetStringComponent(name string) string {
	return string(c.GetComponent(name))
}

type Component struct {
	Name string
	Data []byte
}

func CreateComponent(name string, data []byte) Component {
	return Component{
		Name: name,
		Data: data,
	}
}

func CreateStringComponent(name string, data string) Component {
	return Component{
		Name: name,
		Data: []byte(data),
	}
}
