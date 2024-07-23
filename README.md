# unsmart-net-tools-osiface-server

## What

This is an extension [unsmart-net-tools](https://github.com/Snorkungen/unsmart-net-tools) project. unsmart-net-tools is a webapplication that aims to emulate the TCP/IP stack in the browser.

osiface-server would act as a gateway, allowing IP packets generated on the browser to communicate with the host local area network.

## How

The unsmart-net-tools application relies on an abstraction called interfaces to transport packets to another Interface object. So relying on that fact, an OSInterface object would take the packet information and give it to the osiface-server, which would the forward it out through the servers host operating system.

![](./doc/diagram.svg)

#### Client side

The client being the OSInterface object that operating in the browser. Would first establish a WebSocket connection with the osiface-server. And the register the OSInterface as a client to the server. The server will respond with a client-id and some configuration information, including what destinations (IP addresses), that the server is able to communicate with.

#### Server side

When registering a client the server, the server assigns a unique client id, that it expects to receive from future communication with the client. When the server receives a request to forward a packet the server, translates the IP addresses of the received packet, to a address pair that is native to the local network. Furthermore the server the forwards the packet, through the operating system, and the listens for a response/responses to the forwarded packet. If the server receives a response to a forwarded packet, then the server would forward the received packet to the registered client, using the established WebSocket connection.

## Get Started

> TODO

## Server comments
> Current implementation using linux sockets does not work with TCP

### Client-Server communication
The client and server communicate using a WebSocket connection, exchanging binary data. Each message **MUST** begin with a 14-byte header. The message header has the following fields in order:
- Version
- Opcode
- Client ID
- Transaction ID
- Ethertype

> The above fields are sent as big-endian values.

![](./doc/binary-message-header.svg)
*structure of the binary messages*

The `Version` field **MUST** always be 0x1. The `Opcode` field informs the receiver what the message kind is. The following opcodes are:
- INIT (0x1)
- REPLY (0x2)
- SEND_PACKET (0x8)

An `INIT` message is sent when the WebSocket client wants to initialize a client, the WebSocket Client **SHOULD** fill the transaction with a unique value.

A `REPLY` message is sent from the server when replying to client message, the reply messages transaction id field must correspond to message transaction id the server is replying to. If the server is responding to an `INIT` message the client id field must contain a unique id for the WebSocket connection.

A `SEND_PACKET` message can be sent from either client or server. The client id and ethertype **MUST** be given.

The `Client ID` **MUST** only be unique per WebSocket connection.

The `Transaction ID` exists to allow a single WebSocket client, to have multiple server clients.
