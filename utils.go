package main

import "encoding/binary"

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

// alias to allow for usage as Reader and Writer
type bucket []byte

func (b bucket) Read(p []byte) (int, error) {
	copy(p, b)
	return len(b), nil
}
func (b bucket) Write(p []byte) (int, error) {
	copy(b, p)
	return len(p), nil
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
