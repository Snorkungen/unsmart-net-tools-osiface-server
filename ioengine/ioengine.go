package ioengine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Snorkungen/unsmart-net-tools-osiface-server/internal"
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

func replace_routing_information_ip4(data internal.Bucket, saddr [4]byte, daddr [4]byte, protocol uint8, sport uint16, dport uint16) error {
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
	checksum := internal.CalculateChecksum(data[0:offset])
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
				checksum := internal.CalculateChecksum(data[offset:])
				binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(icmphdr.Checksum)):], checksum) // I do not like magic numbers
			}
		default:
			{
				// if type is not explicitly handled the the type should not be forwarded Either way
				return fmt.Errorf("ICMP(4) type: %d not handled", icmphdr.Type)
			}
		}
	} else if protocol != hdr.Protocol {
		return fmt.Errorf("protocol does match header protocol, expected %d, received %d", protocol, hdr.Protocol)
	}

	tmp := make(internal.Bucket, pseudohdr_size)
	binary.Write((tmp), binary.BigEndian, &pseudohdr)

	var psuedohdr_csum = internal.CalculateChecksum((tmp)) // pseudohdr size is a multiple of 16-bits

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
		checksum := internal.ConcatChecksum(psuedohdr_csum, internal.CalculateChecksum(data[offset:]))

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
		checksum := internal.ConcatChecksum(psuedohdr_csum, internal.CalculateChecksum(data[offset:hdr.TotalLength]))
		// set the tcp checksum
		binary.BigEndian.PutUint16(data[offset+int(unsafe.Offsetof(tcphdr.Checksum)):], checksum)
	}

	return nil
}

func read_packet_data(ethertype uint, data internal.Bucket) (saddr, daddr []byte, protocol int, sport, dport int) {
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

type Client interface{}
type Transaction struct {
	Client Client

	// Either (IPv4) or (IPv6)
	Ethertype int // An enum for the type ether type i.e IP version
	Protocol  int // An enum for the upper layer protocol type

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

func (nm *NATMan) Get(destination net.IP) (target_saddr, target_daddr net.IP, target_sport uint16, err error) {
	sourcer, isused := nm.source_destination_lookup[destination.String()]

	// TODO: this should actually lock because different threads can touch this memory at once

	if !isused {
		return target_saddr, target_daddr, target_sport, fmt.Errorf("destination not found")
	}

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

// Begin of recreating the ioengine monstrosity
type IOEngine struct {
	sending_socket4    int
	transactions       []Transaction
	transactions_mutex sync.RWMutex
	natman             NATMan

	forward_received *func(Client, int, []byte)
}

// remove all references to client int transactions
func (engine *IOEngine) ReleaseClient(client Client) {
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

func (engine *IOEngine) match_received_packet_with_transaction(ethertype uint, data internal.Bucket) (matched_transactions []*Transaction) {
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

	matched_transactions = make([]*Transaction, 0, len(engine.transactions))

	for i, transaction := range engine.transactions {
		if ethertype != uint(transaction.Ethertype) {
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

		if transaction.Protocol != protocol {
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
func (engine *IOEngine) transaction_open(client Client, ethertype uint, data internal.Bucket) (*Transaction, error) {
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

		if transaction.Ethertype != int(ethertype) {
			continue // ethertypes do not match
		}

		if transaction.Protocol != protocol {
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

	var transaction Transaction

	transaction.references = 1
	transaction.Client = client
	transaction.Ethertype = int(ethertype)

	transaction.Protocol = protocol

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
	if !(transaction.Protocol == syscall.IPPROTO_UDP || transaction.Protocol == syscall.IPPROTO_TCP) {
		transaction.Target_sport = 0
		transaction.Target_dport = 0
	}

	engine.transactions = append(engine.transactions, transaction)

	PutListenerTransaction(transaction)

	return &engine.transactions[len(engine.transactions)-1], nil
}

// modify the fields of the packet data for packets coming from the OS
func (engine *IOEngine) transaction_in_process(trans Transaction, data internal.Bucket) error {
	var err error

	/* Note that the for incoming packets the source and destination are swapped*/

	if trans.Ethertype == syscall.ETH_P_IP {
		err = replace_routing_information_ip4(data,
			[4]byte(trans.Source_daddr),
			[4]byte(trans.Source_saddr),
			uint8(trans.Protocol),
			uint16(trans.Source_dport),
			uint16(trans.Source_sport),
		)
	} else {
		return fmt.Errorf("unsupported transaction type")
	}

	return err
}

// modify the fields of the packet data for packets going to the OS
func (engine *IOEngine) transaction_out_process(trans Transaction, data internal.Bucket) error {
	var err error

	if trans.Ethertype == syscall.ETH_P_IP {
		err = replace_routing_information_ip4(data,
			[4]byte(trans.Target_saddr),
			[4]byte(trans.Target_daddr),
			uint8(trans.Protocol),
			uint16(trans.Target_sport),
			uint16(trans.Target_dport),
		)

	} else {
		return fmt.Errorf("unsupported transaction type")
	}

	return err
}

func (engine *IOEngine) SendPacket(client Client, ethertype uint, packet_data []byte) error {
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

func (engine *IOEngine) StartListening() {
	err := AttachListeners()
	if err != nil {
		log.Fatal("attaching ebpf", err)
		return
	}

	// start listening
	go ReceiveAndForward2(engine)
}

func (engine *IOEngine) Init() {
	var err error

	engine.sending_socket4, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		engine.sending_socket4 = -1
	}

	// initialize transactions stuff
	engine.transactions = make([]Transaction, 0)
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

func (engine *IOEngine) SetPacketReceiver(f func(Client, int, []byte)) {
	engine.forward_received = &f
}
