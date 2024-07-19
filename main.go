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

	"github.com/gorilla/websocket"
)

// TODOs
// [/] Refactor messaging between WS-client and WS-server, some abstraction
// [ ] Rework NATMan the adding of source destination objects are a bit whacky
// Refactor entire program and structure the logic and structures and naming

// Checksum implementation inspired by <https://datatracker.ietf.org/doc/html/rfc1071#section-4.1>
func calculate_checksum(buf []byte) uint16 {
	var sum uint32 = 0

	for i := 0; i < len(buf)-1; i += 2 {
		sum += uint32((uint16(buf[i]) << 8) | uint16(buf[i+1]))
	}

	// If the number of bytes was odd, add the last byte
	if len(buf)&1 != 0 {
		sum += (uint32(buf[len(buf)-1])) << 8
	}

	// fold 32-bit sum to 16 bits
	for sum>>16 > 0 { // same thing as sum & 0xFFFF0000 > 0
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

// add to two checsums togheter, ONLY WORKS if csum1 was derrived from a byte array with a size that is divisble by 2
func concat_checksum(csum1 uint16, csum2 uint16) uint16 {
	var sum uint32 = uint32(csum1) + uint32(csum2)
	if sum>>16 > 0 { // something about a carry bit
		sum = (sum & 0xffff) + 1
	}

	if sum == 0xFFFF {
		return 0
	}

	return uint16(sum)
}

const (
	ETH_IP = 0x0800
)

var (
	transactions       []transaction
	transactions_mutex sync.RWMutex

	natman NATMan = NATMan{
		map[string]struct {
			target_daddr net.IP
			target_saddr net.IP
			port         uint16
		}{
			string([]byte{10, 1, 1, 40}): {
				target_daddr: []byte{127, 0, 0, 1},
				target_saddr: []byte{127, 48, 0, 1},
				port:         30000,
			},
			string([]byte{127, 0, 0, 1}): {
				target_daddr: []byte{127, 0, 0, 1},
				target_saddr: []byte{127, 48, 0, 1},
				port:         30000,
			},
		},
	}
)

type bucket []byte

func (b bucket) Read(p []byte) (int, error) {
	copy(p, b)
	return len(b), nil
}
func (b bucket) Write(p []byte) (int, error) {
	copy(b, p)
	return len(p), nil
}

type UDPHeader struct {
	Sport    uint16
	Dport    uint16
	Length   uint16
	Checksum uint16
}

type TCPHeader struct {
	Sport    uint16
	Dport    uint16
	_        [12]byte // contains fields that are not needed for nat ops
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
	Ethertype uint16 // ETH_IP (0x800)
}

// basically just a wrapper for the Websocket connection that allows me to create methods
// create a wrapper for the thing that creates method for reading the binary message format

type client struct {
	// some reference to the ws connection
	conn         *websocket.Conn
	transactions []*transaction
	id           int

	// some reference to the open transactions
}

func (clnt *client) Close() {
	// issue a marker that the transactions are about to close

	// this is dangerous territory because the client contains a slice of pointers to the global transactions
	{
		transactions_mutex.Lock()

		var none_client client
		for _, ptr := range clnt.transactions {
			(*ptr).references = 0       // set the reference count to zero so the next time someone opens the transaction get's deleted
			(*ptr).Client = none_client // just incase so nothing dumb happens if the ws connection is closed
		}

		transactions_mutex.Unlock()
	}

	if clnt.conn == nil {
		return
	}

	clnt.conn.Close() // close ws-socket connection
	clnt.conn = nil
	clnt.transactions = clnt.transactions[0:0]

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

type transaction struct {
	Client client

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

type NATMan struct {
	// fields that would have some kind of meaning etc...

	source_destination_lookup map[string]struct {
		target_daddr net.IP
		target_saddr net.IP
		port         uint16
	}
}

func (nm *NATMan) Get(destination net.IP) (target_saddr, target_daddr net.IP, target_sport uint16, err error) {
	sourcer, isused := nm.source_destination_lookup[string(destination)]

	// TODO: this should actually lock because different threads can touch this memory at once

	if !isused {
		return target_saddr, target_daddr, target_sport, fmt.Errorf("destination not found")
	}

	target_saddr = make(net.IP, len(destination))
	target_daddr = make(net.IP, len(destination))

	// TODO: get a target source address from a selection of multiple choices maybe ???
	copy(target_saddr, sourcer.target_saddr)

	copy(target_daddr, sourcer.target_daddr)

	// then sourcer would contain information that would allow the thing to operate and

	sourcer.port += 1
	target_sport = sourcer.port

	return target_saddr, target_daddr, target_sport, nil
}

func replace_routing_information_ip4(data *bucket, saddr [4]byte, daddr [4]byte, protocol uint8, sport uint16, dport uint16) error {
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
	checksum := calculate_checksum((*data)[0:offset])
	binary.BigEndian.PutUint16((*data)[10:], checksum)

	var pseudohdr PseudoIPv4Header
	var pseudohdr_size = 12

	pseudohdr.Saddr = hdr.Saddr
	pseudohdr.Daddr = hdr.Daddr
	pseudohdr.Protocol = hdr.Protocol
	/* this thing could cause a problem but we're fine right */
	pseudohdr.Length = hdr.TotalLength - uint16(hdr.HeaderLength())

	if protocol != hdr.Protocol {
		// if the packet is not an icmp error the quit
		return fmt.Errorf("not supported reading icmp errors")
	}

	tmp := make(bucket, pseudohdr_size)
	binary.Write((tmp), binary.BigEndian, &pseudohdr)

	var psuedohdr_csum = calculate_checksum((tmp)) // pseudohdr size is a multiple of 16-bits

	if hdr.Protocol == syscall.IPPROTO_UDP {
		// read udp header
		var udphdr UDPHeader
		binary.Read((*data)[offset:], binary.BigEndian, &udphdr)

		pseudohdr.Length = udphdr.Length
		pseudohdr.Protocol = syscall.IPPROTO_UDP

		// modify the port fields
		udphdr.Sport = sport
		udphdr.Dport = dport

		// reset the checsum
		udphdr.Checksum = 0

		// write the udp data onto the data
		binary.Write((*data)[offset:], binary.BigEndian, &udphdr)

		// concatenate the checsum of the pseudohdr data and the udp header data
		checksum := concat_checksum(psuedohdr_csum, calculate_checksum((*data)[offset:]))

		// set the udp checksum
		binary.BigEndian.PutUint16((*data)[offset+6:], checksum)

	} else if hdr.Protocol == syscall.IPPROTO_TCP {
		// read udp header
		var tcphdr TCPHeader
		binary.Read((*data)[offset:], binary.BigEndian, &tcphdr)

		pseudohdr.Protocol = syscall.IPPROTO_TCP

		// modify the port fields
		tcphdr.Sport = sport
		tcphdr.Dport = dport

		// reset the checsum
		tcphdr.Checksum = 0

		// write the tcp header data onto the data
		binary.Write((*data)[offset:], binary.BigEndian, &tcphdr)

		// write the pseudohdr into a buffer so the checksum can be calculated
		checksum := concat_checksum(psuedohdr_csum, calculate_checksum((*data)[offset:hdr.TotalLength]))
		// set the tcp checksum
		binary.BigEndian.PutUint16((*data)[offset+6:], checksum)
	}

	return nil
}

func read_packet_data(ethertype uint, data bucket) (saddr, daddr []byte, protocol int, sport, dport int) {
	var offset int = 0
	if ethertype == ETH_IP {
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

func match_received_packet_with_transaction(ethertype uint, data bucket) (matched_transactions []*transaction) {
	saddr, daddr, protocol, sport, dport := read_packet_data((ethertype), data)

	/* Read transactions and find the requisite transactions*/
	transactions_mutex.RLock()
	defer transactions_mutex.RUnlock()

	matched_transactions = make([]*transaction, 0, len(transactions))

	for i, transaction := range transactions {
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
			/* TODO: allow ICMP errors to be matched with a transaction */
			continue
		}

		if transaction.Target_sport != dport || transaction.Target_dport != sport {
			continue /* ports do not match */
		}

		/* So what now do we do with the transactions */

		/* now do the same magic where the data in the packet is modified and other stuff */
		matched_transactions = append(matched_transactions, &transactions[i])
	}

	return matched_transactions
}

/* read the packet data and create a transaction structure and allows the user to do stuff, if open transaction exist reuse the same transactions */
// either returns the an existing transaction or creates a new transaction
func Transaction_open(client client, ethertype uint, data bucket) (*transaction, error) {
	saddr, daddr, protocol, sport, dport := read_packet_data((ethertype), data)
	/* determine if there is already an existing transaction from the same thing */

	// there is a problem as to how does the thing that needs the transaction
	// reference count
	transactions_mutex.Lock()
	defer transactions_mutex.Unlock()

	for i := 0; i < len(transactions); i++ {
		transaction := transactions[i]

		if transaction.references == 0 {
			// this has been marked to be removed, no one should be using this transaction
			// delete the transaction

			// how does this work
			// <https://stackoverflow.com/a/37335777>
			transactions[i] = transactions[len(transactions)-1]
			transactions = transactions[:len(transactions)-1]

			i -= 1 // since an element has ben removed then the slice gets removed
			continue
		}

		// TODO: a better understanding of what does the comparison of client mean
		if transaction.Client.conn != client.conn || transaction.Client.id != client.id {
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
		transactions[i].references += 1

		return &transactions[i], nil
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
	target_saddr, target_daddr, target_sport, err := natman.Get(daddr)
	if err != nil {
		return nil, err
	}

	transaction.Target_saddr = target_saddr
	transaction.Target_daddr = target_daddr
	transaction.Target_sport = int(target_sport)
	transaction.Target_dport = dport

	transactions = append(transactions, transaction)

	return &transactions[len(transactions)-1], nil
}

/* modify the fileds of the data  */
func Transaction_out_process(trans *transaction, data *bucket) error {
	var err error

	if trans.Type == ETH_IP {
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

func Transaction_in_process(trans transaction, data *bucket) error {
	var err error

	/* Note that the for incoming packets the source and destination are swapped*/

	if trans.Type == ETH_IP {
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

// host to short
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, (i))
	return binary.BigEndian.Uint16(b)
}

// net to host short
func ntohs(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}

func main() {
	addr := "0.0.0.0:7000"

	sending4_socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		sending4_socket = -1
	}

	listening_socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err == nil {
		/* Listen to the OS incoming packets */
		go func() {
			for {
				// A fun thing could be creating a free-list of buffers
				buffer := make([]byte, 1600)
				data_len, from, err := syscall.Recvfrom(listening_socket, buffer, 0)

				if err != nil {
					continue
				}

				sa := from.(*syscall.SockaddrLinklayer)

				// Nah man just spin up another thread, thread pool maybe ???
				// Yes! this allows me to overengineer this, by for example creating a pool routines that have qeues of packets awating processing
				go func(ethertype uint16, data bucket) {
					matches := match_received_packet_with_transaction(uint(ethertype), data)

					if len(matches) == 0 {
						return
					}

					for _, t := range matches {
						// overwrite the data with for each match because the processing function do not read the data
						err := Transaction_in_process(*t, &data)

						if err != nil {
							continue
						}

						// Forward packet to client
						t.Client.SendPacket(ethertype, data)
					}
				}(ntohs(sa.Protocol), buffer[:data_len])
			}
		}()
	}

	var upgrader websocket.Upgrader
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)

		if err != nil {
			log.Fatal(err)
			return
		}

		log.Println("Connection opened")

		// It would be nice if this connection would be attached to some kind of global context

		// this thing has to contain the place all the logic for the instance of the wsconnection
		var clients []client = make([]client, 0)
		var hdr OSIFSHeader

		conn.SetCloseHandler(func(code int, text string) error {
			log.Println("Connection closed")

			for i := range clients {
				clients[i].Close() // loop through and cleanup stuff
			}

			return nil
		})

	ws_message_read_loop:
		for {
			tpe, data, err := conn.ReadMessage()
			if err != nil {
				break
			}

			if tpe != websocket.BinaryMessage {
				continue
			}

			hdr = OSIFSHeader{}
			binary.Read(bucket(data), binary.BigEndian, &hdr)

			if hdr.Version != OSIFS_VERSION {
				continue // version mismatch
			}

			switch hdr.Opcode {
			case OSIFS_OP_INIT:
				{
					// handle initialize the client

					clients = append(clients, client{
						id:           len(clients) + 1, // the client id only needs to be unique for each websocket connection
						conn:         conn,
						transactions: make([]*transaction, 0),
					})

					client := clients[len(clients)-1]

					// this is wher it would be good to have a abstraction that does the reading and logic that i require
					client.SendReply(hdr.Xid, struct{}{}) // client expects at least {} return value to be an object, although In EcmaScript everything is an object

					continue ws_message_read_loop
				}
			case OSIFS_OP_SEND_PACKET:
				{
					if hdr.Ethertype == ETH_IP && sending4_socket < 0 {
						continue ws_message_read_loop // no working sending socket
					}
					// receive packet i.e. forward packet to through the os

					// get the associated client
					var client client
					for i := range clients {
						if hdr.Cid == uint32(clients[i].id) {
							client = clients[i]
							break
						}
					}

					if client.id == 0 {
						// associated client not found
						continue ws_message_read_loop
					}

					packet_data := bucket(data[OSIFS_HEADER_LENGTH:])

					t, err := Transaction_open(client, uint(hdr.Ethertype), packet_data)
					if err != nil {
						// respond with error maybe
						log.Fatal(err)
						continue ws_message_read_loop
					}

					Transaction_out_process(t, &packet_data)

					if t.Type == ETH_IP && sending4_socket > 0 {
						sa := syscall.SockaddrInet4{
							Port: 0,
							Addr: [4]byte(t.Target_daddr),
						}
						err := syscall.Sendto(sending4_socket, packet_data, 0, &sa)
						if err != nil {
							log.Fatal(err)
							continue ws_message_read_loop
						}
					}
				}

			}
		}
	})

	/* start http server */
	fmt.Printf("Server started at: %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

func main__() {
	buffer := bucket{
		0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x3c, 0xba, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
		0x00, 0x01, 0x10, 0xc1, 0xc8, 0xb4, 0x8f, 0x53, 0x13, 0x0a, 0x02, 0x60, 0xae, 0xec, 0xa0, 0x12,
		0xff, 0xcb, 0xfe, 0x30, 0x00, 0x00, 0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x70, 0xa2,
		0xe7, 0x2e, 0x70, 0xa2, 0xe7, 0x2e, 0x01, 0x03, 0x03, 0x07, 0x70,
	}

	fmt.Println(calculate_checksum(buffer))

	// binary.Write(bucket(ip_data[20:]), binary.BigEndian, &UDPHeader{Sport: 100, Dport: 6000})

	// t, err := Transaction_open(client{}, ETH_IP, ip_data)
	// if err != nil {
	// 	log.Fatal(err)
	// 	return
	// }

	// fmt.Println(t, t == &transactions[0])

	// // fmt.Println("Version", hdr.Version(), "HeaderLength", hdr.HeaderLength(), "saddr", hdr.Saddr)
	// fmt.Println()
}
