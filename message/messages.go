package message

import (
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

type Mail struct {
	h          Header
	Components ComponentList
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

type ComponentList []Component

func (c ComponentList) ToWire() []*wire.Mail_Component {
	output := make([]*wire.Mail_Component, len(c))
	for i, v := range c {
		output[i] = &wire.Mail_Component{
			Type: &v.Name,
			Data: v.Data,
		}
	}
	return output
}

func (c ComponentList) AddComponent(comp Component) {
	c = append([]Component(c), comp)
}

func (c ComponentList) HasComponent(name string) bool {
	for _, v := range c {
		if v.Name == name {
			return true
		}
	}
	return false
}

func (c ComponentList) GetComponent(name string) []byte {
	for _, v := range c {
		if v.Name == name {
			return v.Data
		}
	}
	return nil
}

func (c ComponentList) GetStringComponent(name string) string {
	return string(c.GetComponent(name))
}

type Component struct {
	Name string
	Data []byte
}
