package internal

import "encoding/binary"

// Checksum implementation inspired by <https://datatracker.ietf.org/doc/html/rfc1071#section-4.1> <https://gist.github.com/Snorkungen/9aee12a4a32c9d85e5a72da07a487acf>
func CalculateChecksum(buf []byte) uint16 {
	var sum uint64 = 0
	var i int = 0
	var leftover_count = (len(buf) % 4)

	for ; i < (len(buf) - leftover_count); i += 4 {
		sum += (uint64(buf[i]) << 24) | (uint64(buf[i+1]) << 16) | (uint64(buf[i+2]) << 8) | uint64(buf[i+3])
	}

	switch leftover_count {
	case 1:
		sum += (uint64(buf[i]) << 24)
	case 2:
		sum += (uint64(buf[i]) << 24) | (uint64(buf[i+1]) << 16)
	case 3:
		sum += (uint64(buf[i]) << 24) | (uint64(buf[i+1]) << 16) | (uint64(buf[i+2]) << 8)
	}

	// fold 32-bit sum to 16 bits
	for sum>>16 > 0 { // same thing as sum & 0xFFFF0000 > 0
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return uint16(^sum)
}

// add to two checsums togheter, ONLY WORKS if csum1 was derrived from a byte array with a size that is divisble by 2
func ConcatChecksum(csum1 uint16, csum2 uint16) uint16 {
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
type Bucket []byte

func (b Bucket) Read(p []byte) (int, error) {
	copy(p, b)
	return len(b), nil
}
func (b Bucket) Write(p []byte) (int, error) {
	copy(b, p)
	return len(p), nil
}

// host to short
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, (i))
	return binary.BigEndian.Uint16(b)
}

// net to host short
func Ntohs(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}
