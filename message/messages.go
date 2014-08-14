package message

import (
	"time"

	"airdispat.ch/identity"
	"airdispat.ch/wire"
	"code.google.com/p/goprotobuf/proto"
)

// Mail is the basic form of a user-visible AirDispatch message.
//
// It contains a list of components that effectively serve as a key-value
// dictionary of string -> []byte. Most of the time, the []byte can be
// interpreted as a UTF-8 string.
type Mail struct {
	h          Header
	Components ComponentList
}

// CreateMail will return a new Mail object with the correct header, ready for
// adding components.
func CreateMail(from *identity.Address, ts time.Time, to ...*identity.Address) *Mail {
	header := CreateHeader(from, to...)
	header.Timestamp = ts.Unix()

	return &Mail{
		h:          header,
		Components: make(ComponentList, 0),
	}
}

// CreateMailFromBytes will unmarshall a mail message given its bytes and
// header.
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

// ToBytes will marshal a mail message to its component bytes.
func (m *Mail) ToBytes() []byte {
	wireFormat := &wire.Mail{
		Components: m.Components.toWire(),
	}
	by, err := proto.Marshal(wireFormat)
	if err != nil {
		panic("Can't marshal mail bytes.")
	}

	return by
}

// Type is used to satisfy the (message.Message) interface. Mail objects have type
// wire.MailCode (or "MAI").
func (m *Mail) Type() string {
	return wire.MailCode
}

// Header just returns the stored header with the message.
func (m *Mail) Header() Header {
	return m.h
}

// ComponentList maps keys (strings) to components.
type ComponentList map[string]Component

// toWire will marshal a ComponentList to the wire format.
func (c ComponentList) toWire() []*wire.Mail_Component {
	output := make([]*wire.Mail_Component, len(c))
	i := 0
	for _, v := range c {
		newName := v.Name
		output[i] = &wire.Mail_Component{
			Type: &newName,
			Data: v.Data,
		}
		i++
	}
	return output
}

// AddComponent will add a new component object into the list.
func (c ComponentList) AddComponent(comp Component) {
	c[comp.Name] = comp
}

// HasComponent will return whether a Mail object contains a component.
func (c ComponentList) HasComponent(name string) bool {
	_, ok := c[name]
	return ok
}

// GetComponent will return the []byte associated with a component name.
func (c ComponentList) GetComponent(name string) []byte {
	b, _ := c[name]
	return b.Data
}

// GetStringComponent will return the []byte associated with a component name
// interpreted as UTF-8.
func (c ComponentList) GetStringComponent(name string) string {
	return string(c.GetComponent(name))
}

// ToArray will return the ComponentList as an array of components.
func (c ComponentList) ToArray() []Component {
	var out = make([]Component, len(c))
	var i int
	for _, v := range c {
		out[i] = v
		i++
	}
	return out
}

// Component is a basic unit in an AirDispatch message. It has a name, generally
// a string akin to Apple's bundle ids.
//
// E.G. if I am creating an AirDispatch application at http://airdispat.ch/notes
// I may have a data type called "ch.airdispat.notes.title".
type Component struct {
	Name string
	Data []byte
}

// Key will return the name of the component.
func (c Component) Key() string {
	return c.Name
}

// Value will return the bytes of the component.
func (c Component) Value() []byte {
	return c.Data
}

// String will return the bytes of the component interpreted as UTF-8.
func (c Component) String() string {
	return string(c.Data)
}

// CreateComponent will return a new component given a name and data.
func CreateComponent(name string, data []byte) Component {
	return Component{
		Name: name,
		Data: data,
	}
}

// CreateStringComponent will return a new component given a name and a
// UTF-8 string.
func CreateStringComponent(name string, data string) Component {
	return Component{
		Name: name,
		Data: []byte(data),
	}
}
