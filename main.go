package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"syscall"
	"unsafe"

	"github.com/gorilla/websocket"
)

var (
	ioengine = IOEngine{}
)

type UDPHeader struct {
	Sport    uint16
	Dport    uint16
	Length   uint16
	Checksum uint16
}

type TCPHeader struct {
	Sport    uint16
	Dport    uint16
	P_1      uint32 // contains fields that are not needed for nat ops
	P_2      uint32 // contains fields that are not needed for nat ops
	P_3      uint16 // contains fields that are not needed for nat ops // 12 bytes
	P_4      uint16 // contains fields that are not needed for nat ops // 12 bytes
	Checksum uint16
}

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
}

type PseudoIPv4Header struct {
	Saddr    [4]byte
	Daddr    [4]byte
	_        uint8
	Protocol uint8
	Length   uint16
}

type IPv4Header struct {
	P_version_ihl       uint8
	ServiceType         uint8
	TotalLength         uint16
	Identification      uint16
	P_flags_frag_offset uint16
	TTL                 uint8
	Protocol            uint8
	Checksum            uint16
	Saddr               [4]byte
	Daddr               [4]byte
}

func (hdr IPv4Header) Version() uint8 {
	return hdr.P_version_ihl >> 4
}
func (hdr IPv4Header) HeaderLength() uint8 {
	return hdr.P_version_ihl & 0x0f << 2
}

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

type transaction struct {
	Client *client

	Type  int // An enum for the type ether type i.e IP version
	Proto int // An enum for the upper layer protocol type

	// Source refers to information that the browser client understand
	Source_sport int
	Source_dport int
	Source_saddr net.IP
	Source_daddr net.IP

	// Target refers to what the operating system target device
	Target_sport int
	Target_dport int
	Target_saddr net.IP
	Target_daddr net.IP

	references int // a reference count that does stuff i guess
}

type natman_lookup_entry struct {
	target_daddr net.IP
	target_saddr net.IP
	port         uint16
}
type NATMan struct {
	// fields that would have some kind of meaning etc...
	source_destination_lookup map[string]natman_lookup_entry
}

func (nm *NATMan) Get(destination net.IP) (target_saddr, target_daddr []byte, target_sport uint16, err error) {
	sourcer, isused := nm.source_destination_lookup[destination.String()]

	// TODO: this should actually lock because different threads can touch this memory at once

	if !isused {
		return target_saddr, target_daddr, target_sport, fmt.Errorf("destination not found")
	}

	target_saddr = make(net.IP, len(sourcer.target_saddr))
	target_daddr = make(net.IP, len(sourcer.target_daddr))

	// detect the network family
	if tmp := destination.To4(); tmp != nil {
		// addres is ipv4
		target_saddr = make([]byte, net.IPv4len)
		copy(target_saddr, sourcer.target_saddr.To4())
		target_daddr = make([]byte, net.IPv4len)
		copy(target_daddr, sourcer.target_daddr.To4())
	} else {
		// address is ipv6
		target_saddr = make([]byte, net.IPv6len)
		copy(target_saddr, sourcer.target_saddr.To16())
		target_daddr = make([]byte, net.IPv6len)
		copy(target_daddr, sourcer.target_daddr.To16())
	}

	sourcer.port += 1
	target_sport = sourcer.port

	// just copy over the updated values into the lookup table
	nm.source_destination_lookup[destination.String()] = sourcer

	return target_saddr, target_daddr, target_sport, nil
}

func replace_routing_information_ip4(data bucket, saddr [4]byte, daddr [4]byte, protocol uint8, sport uint16, dport uint16) error {
	var offset int = 0

	/* Read IP Header */
	var hdr IPv4Header
	binary.Read(data, binary.BigEndian, &hdr)

	// increment offset by the
	offset += int(hdr.HeaderLength())

	// Replace the addresses
	hdr.Saddr = [4]byte(saddr)
	hdr.Daddr = [4]byte(daddr)

	// reset checksum
	hdr.Checksum = 0

	// write header into the data
	binary.Write(data, binary.BigEndian, &hdr)

	if offset > 20 {
		return fmt.Errorf("unsupported data ip header with options")
	}

	// recalculate and set the new checksum
	checksum := calculate_checksum(data[0:offset])
	binary.BigEndian.PutUint16(data[int(unsafe.Offsetof(hdr.Checksum)):], checksum)

	var pseudohdr PseudoIPv4Header
	var pseudohdr_size = 12

	pseudohdr.Saddr = hdr.Saddr
	pseudohdr.Daddr = hdr.Daddr
	pseudohdr.Protocol = hdr.Protocol
	/* this thing could cause a problem but we're fine right */
	pseudohdr.Length = hdr.TotalLength - uint16(hdr.HeaderLength())

	if hdr.Protocol == syscall.IPPROTO_ICMP {
		/* create an attempt at handling packets */

		// read icmp header
		var icmphdr ICMPHeader
		binary.Read(data[offset:], binary.BigEndian, &icmphdr)

		switch icmphdr.Type {
		case 0:
		case 8:
			{
			} // noop
		case 3: // Handle destination unreachable
			{
				// recursive call, +"4" is unused header field
				replace_routing_information_ip4(data[offset+int(unsafe.Sizeof(icmphdr))+4:], saddr, daddr, protocol, sport, dport)

				// recalculate, icmp header checsum
				binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(icmphdr.Checksum)):], 0) // set the checksum field to zero

				// write the checksum value into the icmp checksum field
				checksum := calculate_checksum(data[offset:])
				binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(icmphdr.Checksum)):], checksum) // I do not like magic numbers
			}
		default:
			{
				// if type is not explicitly handled the the type should not be forwarded Either way
				return fmt.Errorf("ICMP(4) type: %d not handled", icmphdr.Type)
			}
		}
	} else if protocol != hdr.Protocol {
		return fmt.Errorf("protocol does match header protocol")
	}

	tmp := make(bucket, pseudohdr_size)
	binary.Write((tmp), binary.BigEndian, &pseudohdr)

	var psuedohdr_csum = calculate_checksum((tmp)) // pseudohdr size is a multiple of 16-bits

	if hdr.Protocol == syscall.IPPROTO_UDP {
		// read udp header
		var udphdr UDPHeader
		binary.Read(data[offset:], binary.BigEndian, &udphdr)

		pseudohdr.Length = udphdr.Length
		pseudohdr.Protocol = syscall.IPPROTO_UDP

		// modify the port fields
		udphdr.Sport = sport
		udphdr.Dport = dport

		// reset the checsum
		udphdr.Checksum = 0

		// write the udp data onto the data
		binary.Write(data[offset:], binary.BigEndian, &udphdr)

		// concatenate the checsum of the pseudohdr data and the udp header data
		checksum := concat_checksum(psuedohdr_csum, calculate_checksum(data[offset:]))

		// set the udp checksum
		binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(udphdr.Checksum)):], checksum)
	} else if hdr.Protocol == syscall.IPPROTO_TCP {
		// read udp header
		var tcphdr TCPHeader
		binary.Read(data[offset:], binary.BigEndian, &tcphdr)

		pseudohdr.Protocol = syscall.IPPROTO_TCP

		// modify the port fields
		tcphdr.Sport = sport
		tcphdr.Dport = dport

		// reset the checsum
		tcphdr.Checksum = 0
		// write the tcp header data onto the data
		binary.Write(data[offset:], binary.BigEndian, &tcphdr)

		// write the pseudohdr into a buffer so the checksum can be calculated
		checksum := concat_checksum(psuedohdr_csum, calculate_checksum(data[offset:hdr.TotalLength]))
		// set the tcp checksum
		binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(tcphdr.Checksum)):], checksum)
	}

	return nil
}

func read_packet_data(ethertype uint, data bucket) (saddr, daddr []byte, protocol int, sport, dport int) {
	var offset int = 0
	if ethertype == syscall.ETH_P_IP {
		var hdr IPv4Header
		binary.Read(data, binary.BigEndian, &hdr)

		saddr = make(net.IP, len(hdr.Saddr))
		daddr = make(net.IP, len(hdr.Daddr))
		copy(saddr, hdr.Saddr[:])
		copy(daddr, hdr.Daddr[:])

		protocol = int(hdr.Protocol)

		offset += int(hdr.HeaderLength())
	}

	if protocol == syscall.IPPROTO_UDP {
		var udphdr UDPHeader
		binary.Read(data[offset:], binary.BigEndian, &udphdr)

		sport = int(udphdr.Sport)
		dport = int(udphdr.Dport)
	}

	if protocol == syscall.IPPROTO_TCP {
		var tcphdr TCPHeader
		binary.Read(data[offset:], binary.BigEndian, &tcphdr)

		sport = int(tcphdr.Sport)
		dport = int(tcphdr.Dport)
	}

	return saddr, daddr, protocol, sport, dport
}

// Begin of recreating the ioengine monstrosity
type IOEngine struct {
	listening_socket   int
	sending_socket4    int
	transactions       []transaction
	transactions_mutex sync.RWMutex
	natman             NATMan
}

// remove all references to client int transactions
func (engine *IOEngine) ReleaseClient(client *client) {
	engine.transactions_mutex.Lock()

	// remove transactions with client from transactions
	for i := 0; i < len(engine.transactions); i++ {
		if engine.transactions[i].Client != client {
			continue
		}

		engine.transactions[i].references = 0
		engine.transactions[i].Client = nil

		// remove transaction from list
		engine.transactions[i] = engine.transactions[len(engine.transactions)-1] // swap last with current
		engine.transactions = engine.transactions[:len(engine.transactions)-1]   // remove the last from list

		i -= 1 // decrement idx due to transaction now being smaller
	}

	engine.transactions_mutex.Unlock()
}

func (engine *IOEngine) match_received_packet_with_transaction(ethertype uint, data bucket) (matched_transactions []*transaction) {
	saddr, daddr, protocol, sport, dport := read_packet_data((ethertype), data)

	/* TODO: allow ICMP errors to be matched with a transaction */
	/* Only handle  a select few ICMPv4 error codes */
	if protocol == syscall.IPPROTO_ICMP {
		// there should be better way of doing this instead of doing this garbage
		// assume ipv4
		var offset = 0

		// read the iphdr lenght and increment offset
		offset += int(data[0]&0xF) << 2 // some magic bs, I'm tired

		// read icmp header
		var icmphdr ICMPHeader
		binary.Read(data[offset:], binary.BigEndian, &icmphdr)

		// read the icmp type, if
		if icmphdr.Type == 3 || icmphdr.Type == 5 || icmphdr.Type == 11 || icmphdr.Type == 12 || icmphdr.Type == 4 {
			// NOTE: ports are swapped
			_, _, protocol, dport, sport = read_packet_data(ethertype, data[offset+8:]) // magic number location where packet data should exist
		}
	}

	/* Read transactions and find the requisite transactions*/
	engine.transactions_mutex.RLock()
	defer engine.transactions_mutex.RUnlock()

	matched_transactions = make([]*transaction, 0, len(engine.transactions))

	for i, transaction := range engine.transactions {
		if ethertype != uint(transaction.Type) {
			continue // not a match
		}

		/* check that the packet destination matches the transaction source */
		if !bytes.Equal(transaction.Target_saddr, daddr) {
			continue // not for source
		}

		if !bytes.Equal(transaction.Target_daddr, saddr) {
			/* for example if packet is routed but router returns an icmp error something similar */
			/* This is not supported due to how to translate ip addresses to browser network, ???? */
			continue
		}

		if transaction.Proto != protocol {
			continue
		}

		if transaction.Target_sport != dport || transaction.Target_dport != sport {
			continue /* ports do not match */
		}

		/* So what now do we do with the transactions */

		/* now do the same magic where the data in the packet is modified and other stuff */
		matched_transactions = append(matched_transactions, &engine.transactions[i])
	}

	return matched_transactions
}

// Create or reuse a transaction for a packet going to the operating system
func (engine *IOEngine) transaction_open(client *client, ethertype uint, data bucket) (*transaction, error) {
	saddr, daddr, protocol, sport, dport := read_packet_data((ethertype), data)
	/* determine if there is already an existing transaction from the same thing */

	// there is a problem as to how does the thing that needs the transaction
	// reference count
	engine.transactions_mutex.Lock()
	defer engine.transactions_mutex.Unlock()

	for i := 0; i < len(engine.transactions); i++ {
		transaction := engine.transactions[i]

		if transaction.references == 0 {
			// this has been marked to be removed, no one should be using this transaction
			// delete the transaction

			// how does this work
			// <https://stackoverflow.com/a/37335777>
			engine.transactions[i] = engine.transactions[len(engine.transactions)-1]
			engine.transactions = engine.transactions[:len(engine.transactions)-1]

			i -= 1 // since an element has ben removed then the slice gets removed
			continue
		}

		// TODO: a better understanding of what does the comparison of client mean
		if transaction.Client != client {
			continue // client does not match
		}

		if transaction.Type != int(ethertype) {
			continue // ethertypes do not match
		}

		if transaction.Proto != protocol {
			continue // protocol does not match, browser client cannot send icmp errors
		}

		if !bytes.Equal(transaction.Source_saddr, saddr) || !bytes.Equal(transaction.Source_daddr, daddr) {
			continue // addresses do not match
		}

		if transaction.Source_sport != sport || transaction.Source_dport != dport {
			continue // ports do not match
		}

		// have not figured out what this means because when a client closes the transactions should close, but there might be a case when the transaction should get deleted but the client does'nt exist
		engine.transactions[i].references += 1

		return &engine.transactions[i], nil
	}

	var transaction transaction

	transaction.references = 1
	transaction.Client = client
	transaction.Type = int(ethertype)

	transaction.Proto = protocol

	transaction.Source_saddr = saddr
	transaction.Source_daddr = daddr
	transaction.Source_sport = sport
	transaction.Source_dport = dport

	// configure the address and port translations
	// create some stateful object that keeps track of stuff, and does stuff
	target_saddr, target_daddr, target_sport, err := engine.natman.Get(daddr)
	if err != nil {
		return nil, err
	}

	transaction.Target_saddr = target_saddr
	transaction.Target_daddr = target_daddr
	transaction.Target_sport = int(target_sport)
	transaction.Target_dport = dport

	// Quick hack if the protocol is not UDP or TCP the the ports MUST be zero
	if !(transaction.Proto == syscall.IPPROTO_UDP || transaction.Proto == syscall.IPPROTO_TCP) {
		transaction.Target_sport = 0
		transaction.Target_dport = 0
	}

	engine.transactions = append(engine.transactions, transaction)

	return &engine.transactions[len(engine.transactions)-1], nil
}

// modify the fields of the packet data for packets coming from the OS
func (engine *IOEngine) transaction_in_process(trans transaction, data bucket) error {
	var err error

	/* Note that the for incoming packets the source and destination are swapped*/

	if trans.Type == syscall.ETH_P_IP {
		err = replace_routing_information_ip4(data,
			[4]byte(trans.Source_daddr),
			[4]byte(trans.Source_saddr),
			uint8(trans.Proto),
			uint16(trans.Source_dport),
			uint16(trans.Source_sport),
		)
	} else {
		return fmt.Errorf("unsupported transaction type")
	}

	return err
}

// modify the fields of the packet data for packets going to the OS
func (engine *IOEngine) transaction_out_process(trans transaction, data bucket) error {
	var err error

	if trans.Type == syscall.ETH_P_IP {
		err = replace_routing_information_ip4(data,
			[4]byte(trans.Target_saddr),
			[4]byte(trans.Target_daddr),
			uint8(trans.Proto),
			uint16(trans.Target_sport),
			uint16(trans.Target_dport),
		)

	} else {
		return fmt.Errorf("unsupported transaction type")
	}

	return err
}

func (engine *IOEngine) SendPacket(client *client, ethertype uint, packet_data bucket) error {
	if ethertype != syscall.ETH_P_IP {
		return fmt.Errorf("ethertype(%#x) not supported", ethertype)
	}

	if engine.sending_socket4 <= 0 {
		return fmt.Errorf("no sending_socket4 socket")
	}

	// do the actual packet processing, where the client is needed and stuff
	t, err := engine.transaction_open(client, ethertype, packet_data)
	if err != nil {
		return err
	}

	// set the requisite fields for the outgoing packet
	err = engine.transaction_out_process(*t, packet_data)
	if err != nil {
		return err // the packet won't be sent out_process indicated some kind of problem
	}

	// create destination socket address
	sa := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte(t.Target_daddr),
	}

	err = syscall.Sendto(engine.sending_socket4, packet_data, 0, &sa)
	return err
}

func (engine *IOEngine) ReceiveAndForward() error {
	// A fun thing could be creating a free-list of buffers
	buffer := make([]byte, 1600)
	data_len, from, err := syscall.Recvfrom(engine.listening_socket, buffer, 0)

	if err != nil {
		return err
	}

	sa := from.(*syscall.SockaddrLinklayer)

	// Nah man just spin up another thread, thread pool maybe ???
	// Yes! this allows me to overengineer this, by for example creating a pool routines that have qeues of packets awating processing
	go func(ethertype uint16, data bucket) {
		matches := engine.match_received_packet_with_transaction(uint(ethertype), data)

		if len(matches) == 0 {
			return
		}

		for _, t := range matches {
			// overwrite the data with for each match because the processing function do not read the data
			err := engine.transaction_in_process(*t, data)

			if err != nil {
				continue
			}

			// Forward packet to client
			t.Client.SendPacket(ethertype, data)
		}
	}(ntohs(sa.Protocol), buffer[:data_len])

	return nil
}

func (engine *IOEngine) StartListening() {
	if engine.listening_socket < 0 {
		return
	}

	// start listening
	go func() {
		for {
			engine.ReceiveAndForward()
		}
	}()
}

func (engine *IOEngine) Init() {
	var err error

	engine.listening_socket, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		engine.listening_socket = -1 // there was a problem indicate that the there is a problem with the listening
	}

	engine.sending_socket4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		engine.sending_socket4 = -1
	}

	// initialize transactions stuff
	engine.transactions = make([]transaction, 0)
	engine.transactions_mutex = sync.RWMutex{}

	// initialize natman
	if engine.natman.source_destination_lookup == nil {
		engine.natman.source_destination_lookup = make(map[string]natman_lookup_entry)
	}
}

func (engine *IOEngine) SetDestination(str_sdaddr string, str_tsource string, str_tdestination string) {
	var (
		source_daddr net.IP
		target_daddr net.IP
		target_saddr net.IP
	)

	source_daddr = net.ParseIP(str_sdaddr)
	if source_daddr == nil {
		log.Fatal("bad source destination,", str_sdaddr)
	}

	target_daddr = net.ParseIP(str_tdestination)
	if target_daddr == nil {
		log.Fatal("bad target destination,", str_tdestination)
	}

	// !TODO: support target source be a network
	target_saddr = net.ParseIP(str_tsource)
	if target_saddr == nil {
		log.Fatal("bad target source,", str_tsource)
	}

	if len(source_daddr) != len(target_saddr) || len(source_daddr) != len(target_daddr) {
		log.Fatal("ip mismatch")
		return
	}

	engine.natman.source_destination_lookup[(source_daddr).String()] = struct {
		target_daddr net.IP
		target_saddr net.IP
		port         uint16
	}{
		target_daddr: target_daddr,
		target_saddr: target_saddr,
		port:         29900, // arbitrary number to begin port incrementation
	}
}

// basically just a wrapper for the Websocket connection that allows me to create methods
// create a wrapper for the thing that creates method for reading the binary message format
type client struct {
	// some reference to the ws connection
	conn *websocket.Conn
	id   int

	// some reference to the open transactions
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
	msg_data := make(bucket, msg_len)

	binary.Write(msg_data, binary.BigEndian, &hdr) // write header into send buffer
	copy(msg_data[OSIFS_HEADER_LENGTH:], message)  // copy message into send buffer

	// pollute log
	log.Printf("Sending message to client, version: %d, opcode: %d, cid: %d, xid: %d, ethertype: %d\n", hdr.Version, hdr.Opcode, hdr.Cid, hdr.Xid, hdr.Ethertype)

	clnt.conn.WriteMessage(websocket.BinaryMessage, msg_data) // Send msg to ws-client
}

// Server can only send packets and replies
func (clnt *client) SendPacket(ethertype uint16, message []byte) {
	clnt.send(OSIFS_OP_SEND_PACKET, ethertype, 0, message)
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

func (wsch *WSClientHandler) Handle(data bucket, r *http.Request) {
	var hdr = OSIFSHeader{}
	binary.Read(bucket(data), binary.BigEndian, &hdr)

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

func (wsch *WSClientHandler) HandleInit(hdr OSIFSHeader, _ bucket) {
	wsch.clients = append(wsch.clients, client{
		id:   len(wsch.clients) + 1, // the client id only needs to be unique for each websocket connection
		conn: wsch.conn,
	})

	client := wsch.clients[len(wsch.clients)-1]

	// this is wher it would be good to have a abstraction that does the reading and logic that i require
	client.SendReply(hdr.Xid, struct{}{}) // client expects at least {} return value to be an object, although In EcmaScript everything is an object
}

func (wsch *WSClientHandler) HandleSendPacket(hdr OSIFSHeader, data bucket) {
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
