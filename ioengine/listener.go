package ioengine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/Snorkungen/unsmart-net-tools-osiface-server/internal"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

/*
	Provide functions to deal with the operating system etc..
*/

// system-endian
type PacketKey struct {
	ethertype uint16
	protocol  uint16 // should be a byte but for alignment purposes
	sport     uint16
	dport     uint16
	saddr     [16]byte
	daddr     [16]byte
}

var objs xdppObjects

func AttachListeners() error {
	// Remove resorce limits for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Load the eBPF program into kernel
	if err := loadXdppObjects(&objs, nil); err != nil {
		return err
	}

	// Iterate Ethernet interfaces and attach program
	ifaces, err := net.Interfaces()
	if err != nil {
		return errors.Join(fmt.Errorf("fetching interfaces"), err)
	}

	for _, ifi := range ifaces {
		// Just hope that all interfaces are Ethernet

		// Attach loaded program to interface
		_, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.MatchPackets,
			Interface: ifi.Index,
		})

		if err != nil {
			return errors.Join(fmt.Errorf("attaching XDP to iface: %d", ifi.Index), err)
		}

		// The link should close when the main process exits
		// defer link.Close()
	}

	return nil
}

func transaction2pkey(t Transaction) PacketKey {
	pkey := PacketKey{
		ethertype: uint16(t.Ethertype),
		protocol:  uint16(t.Protocol),
		// ports are swapped, because receiving
		sport: uint16(t.Target_dport),
		dport: uint16(t.Target_sport),
		saddr: [16]byte{},
		daddr: [16]byte{},
	}

	// set the addresses, NOTE Source and Destination are swapped
	if len(t.Target_daddr) == 4 {
		copy(pkey.saddr[12:], t.Target_daddr)
	} else {
		copy(pkey.saddr[:], t.Target_daddr)
	}

	if len(t.Target_saddr) == 4 {
		copy(pkey.daddr[12:], t.Target_saddr)
	} else {
		copy(pkey.daddr[:], t.Target_saddr)
	}

	return pkey
}

func PutListenerTransaction(t Transaction) {
	pkey := transaction2pkey(t)

	// TODO: have logic that decides if matched packet should be dropped or not
	var value uint64 = 1

	// ignore error failed to set the key
	objs.PacketKeys.Update(pkey, &value, 0)

}

func PopListenerTransaction(t Transaction) {
	pkey := transaction2pkey(t)
	objs.PacketKeys.Delete(pkey)
}

// This function should be its own routine
func ReceiveAndForward2(engine *IOEngine) {
	pb, err := ringbuf.NewReader(objs.PacketBuffer)
	if err != nil {
		log.Fatal("creating PacketBuffer reader", err)
		return
	}

	for {
		record, err := pb.Read()
		if err != nil {
			log.Fatal("reading from PacketBuffer")
			return
		}

		// read the data length
		data_length := binary.BigEndian.Uint16(record.RawSample)
		if data_length < 14 {
			data_length = uint16(len(record.RawSample)) // in-case of something being wrong
		}
		// first 14-bytes are ethernet
		var ethertype uint16 = binary.BigEndian.Uint16(record.RawSample[12:])

		go func(ethertype uint16, data internal.Bucket) {
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
				if engine.forward_received != nil {
					(*engine.forward_received)(t.Client, t.Ethertype, data)
				}
			}
		}(ethertype, record.RawSample[14:data_length])

		// pass on record
	}
}
