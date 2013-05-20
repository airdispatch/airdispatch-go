airdispatch
============

[![Build Status](https://drone.io/github.com/huntaub/airdispatch-protocol/status.png)](https://drone.io/github.com/huntaub/airdispatch-protocol/latest)

Airdispatch is a new protocol that allows developers to create distributed networked applications without worrying about the backend.

Airdispatch is provided under the [MIT License](https://github.com/huntaub/airdispatch-protocol/blob/master/LICENSE).

### Installing Airdispatch
  1. `git clone` this repository
  2. Rename the created folder to `airdispat.ch`
  3. Drop that folder in your `$GOPATH/src`
  4. `go get ./...`
  5. There is no step 5.

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

### Information on the Provided Client
There are actually *two* provided clients in this repository:

  1. **The WebClient** - Currently, the webclient is used to implement 'email' using the airdispach protocol. This is part of the original project's mission, and will eventually be rolled out into its own repository.
  2. **The CLI** - This is used to test trackers and mailservers. You can interact with both sets of servers in every facet described in the protocol.

We have provided a sample mail server and tracker than you can use to test the protocol with the CLI:
  - Server: `mailserver.airdispat.ch:2048`
  - Tracker: `mailserver.airdispat.ch:1024`

### More Information
For more detailed information, we ask you to visit the wiki or read the original protocol definition.

### Conclusion
We understand that the protocol has a way to go, and we do not believe that it is the final word on distributed communications. However, we hope to open the door to more conversations about federated data in a world where networks are becoming (unfortunately) increasingly centralized.
