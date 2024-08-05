package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/Snorkungen/unsmart-net-tools-osiface-server/internal"
	osengine "github.com/Snorkungen/unsmart-net-tools-osiface-server/ioengine"
	"github.com/gorilla/websocket"
)

var (
	ioengine = osengine.IOEngine{}
)

const (
	OSIFS_HEADER_LENGTH    = 14
	OSIFS_VERSION          = 1
	OSIFS_OP_INIT          = 1
	OSIFS_OP_REPLY         = 2
	OSIFS_OP_FETCH_CLIENTS = 3
	OSIFS_OP_SEND_PACKET   = 8
)

type OSIFSHeader struct {
	Version   uint16 // 0x1
	Opcode    uint16 // INIT(0x1), REPLY(0x2), SEND_PACKET(0x8)
	Cid       uint32
	Xid       uint32
	Ethertype uint16 // IPv4 (0x800)
}

// basically just a wrapper for the Websocket connection that allows me to create methods
// create a wrapper for the thing that creates method for reading the binary message format
type client struct {
	// some reference to the ws connection
	conn *websocket.Conn
	mx   sync.Mutex
	id   int
}

func (clnt *client) Close() {
	// issue a marker that the transactions are about to close
	ioengine.ReleaseClient(clnt)

	if clnt.conn == nil {
		return
	}

	clnt.conn.Close() // close ws-socket connection
	clnt.conn = nil
}

func (clnt *client) send(op uint16, ethertype uint16, xid uint32, message []byte) {
	hdr := OSIFSHeader{
		Version:   OSIFS_VERSION,
		Opcode:    op,
		Cid:       uint32(clnt.id),
		Xid:       xid,
		Ethertype: ethertype,
	}

	msg_len := OSIFS_HEADER_LENGTH + len(message)
	msg_data := make(internal.Bucket, msg_len)

	binary.Write(msg_data, binary.BigEndian, &hdr) // write header into send buffer
	copy(msg_data[OSIFS_HEADER_LENGTH:], message)  // copy message into send buffer

	// pollute log
	log.Printf("Sending message to client, version: %d, opcode: %d, cid: %d, xid: %d, ethertype: %d\n", hdr.Version, hdr.Opcode, hdr.Cid, hdr.Xid, hdr.Ethertype)

	clnt.conn.WriteMessage(websocket.BinaryMessage, msg_data) // Send msg to ws-client
}

// Server can only send packets and replies
func (clnt *client) SendPacket(ethertype uint16, message []byte) {
	clnt.mx.Lock()
	clnt.send(OSIFS_OP_SEND_PACKET, ethertype, 0, message)
	clnt.mx.Unlock()
}

func (clnt *client) SendReply(xid uint32, reply any) {
	message, err := json.Marshal(reply)
	if err != nil {
		log.Fatal("Could not send: ", reply)
		return // this should not fail
	}

	clnt.send(OSIFS_OP_REPLY, 0, xid, message)
}

// WS_client state machine stuff
type WSClientHandler struct {
	conn    *websocket.Conn
	clients []client
}

func (wsch WSClientHandler) get_client_by_id(cid int) *client {
	for i := range wsch.clients {
		if cid == wsch.clients[i].id {
			return &wsch.clients[i]
		}
	}

	return nil
}

func (wsch *WSClientHandler) HandleClose(_ int, _ string) error {
	for i := range wsch.clients {
		wsch.clients[i].Close() // loop through and cleanup stuff
	}

	return nil
}

func (wsch *WSClientHandler) Handle(data internal.Bucket, r *http.Request) {
	var hdr = OSIFSHeader{}
	binary.Read(internal.Bucket(data), binary.BigEndian, &hdr)

	switch hdr.Opcode {
	case OSIFS_OP_INIT:
		log.Printf("message from %s, initializing client", r.RemoteAddr)
		wsch.HandleInit(hdr, data)
	case OSIFS_OP_SEND_PACKET:
		log.Printf("message from %s, received packet forwarding to os", r.RemoteAddr)
		wsch.HandleSendPacket(hdr, data)
	default:
		log.Printf("message from %s, unknown op(%#x), cid(%#x)", r.RemoteAddr, hdr.Opcode, hdr.Cid)
	}
}

func (wsch *WSClientHandler) HandleInit(hdr OSIFSHeader, _ internal.Bucket) {
	wsch.clients = append(wsch.clients, client{
		id:   len(wsch.clients) + 1, // the client id only needs to be unique for each websocket connection
		conn: wsch.conn,
	})

	var client *client = &wsch.clients[len(wsch.clients)-1]

	// this is wher it would be good to have a abstraction that does the reading and logic that i require
	client.SendReply(hdr.Xid, struct{}{}) // client expects at least {} return value to be an object, although In EcmaScript everything is an object
}

func (wsch *WSClientHandler) HandleSendPacket(hdr OSIFSHeader, data internal.Bucket) {
	client := wsch.get_client_by_id(int(hdr.Cid))
	if client == nil {
		return
	}

	packet_data := data[OSIFS_HEADER_LENGTH:]

	ioengine.SendPacket(client, uint(hdr.Ethertype), packet_data)
}

func main() {
	addr := "0.0.0.0:7000"

	// configure and start ioengine
	ioengine.Init()
	ioengine.SetDestination("10.1.1.40", "127.48.0.1", "127.0.0.1")

	ioengine.SetPacketReceiver(func(clnt osengine.Client, ethertype int, data []byte) {
		c := clnt.(*client)
		c.SendPacket(uint16(ethertype), data)
	})
	ioengine.StartListening()

	var upgrader websocket.Upgrader
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)

		if err != nil {
			log.Fatal(err)
			return
		}

		// It would be nice if this connection would be attached to some kind of global context
		var handler = WSClientHandler{
			conn:    conn,
			clients: make([]client, 0, 1),
		}

		// set the  close callback, TODO: tell the below loop to stop reading
		conn.SetCloseHandler(handler.HandleClose)

		log.Printf("connection opened with %s", r.RemoteAddr)

		for {
			tpe, data, err := handler.conn.ReadMessage()

			if err != nil {
				break
			}

			if tpe != websocket.BinaryMessage {
				continue // bad received message ignore
			}

			handler.Handle(data, r)
		}
	})

	/* start http server */
	fmt.Printf("Server started at: %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
