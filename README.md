airdispatch
============

[![GoDoc](https://godoc.org/airdispat.ch?status.svg)](https://godoc.org/airdispat.ch)

Airdispatch is a new protocol that allows developers to create distributed networked applications without worrying about the backend.

Airdispatch is provided under the [MIT License](https://github.com/huntaub/airdispatch-protocol/blob/master/LICENSE).

### Installing Airdispatch

    go get airdispat.ch/message

### A Quick Overview

Airdispatch provides three key components when working with distributed networks:

  1. **Addressing** - Airdispatch creates 'serverless' addresses. That is that actual addresses do not contain the server location where that addresses messages should be sent. Instead, we have included a 'tracker layer' that translates addresses into locations. This allows the user to transistion servers without having to change addresses.
  2. **Message Metadata** - The actual message type provides a method to transmit arbitrary binary data (through the [mail data types](https://github.com/huntaub/airdispatch-protocol/blob/master/airdispatch/Message.proto#L91) object). This means that the protocol can support messages of all shapes and sizes.
  3. **Control** - Unlike email (and other traditional distributed systems), messages are not immediately transmitted to receiving servers. Instead, the originating server will merely store the message and 'ping' the recipient server using the [alert object](https://github.com/huntaub/airdispatch-protocol/blob/master/airdispatch/Message.proto#L56). This means that servers can determine when messages are downloaded (and allow for editing and deleting messages after sending).

Some other benefits include:
  - Security - all messages are signed, actual mail can be encrypted in any arbitrary algorithm
  - Compatibility - all services implementing airdispatch will be inherently compatible (allowing for complex messaging schemes)
  - Public Messages - the current protocol defines a way to create 'public messages' which are viewable by anyone possessing the originating address
  - Privacy - without access to a network's tracking layer, that network will be essentially isolated from the public airdispatch network, providing for private messaging networks
  - Extensibility - because the protocol is built off of proven technologies (like protocol buffers) it is trivial to add extensions

### More Information

For more detailed information about the protocol, please visit our [website](http://airdispat.ch). The wiki has outdated information.
