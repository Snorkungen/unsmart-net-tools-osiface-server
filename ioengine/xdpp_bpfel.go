// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package ioengine

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type xdppPacketKey struct {
	Ethertype uint16
	Protocol  uint16
	Sport     uint16
	Dport     uint16
	Saddr     [16]uint8
	Daddr     [16]uint8
}

// loadXdpp returns the embedded CollectionSpec for xdpp.
func loadXdpp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_XdppBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xdpp: %w", err)
	}

	return spec, err
}

// loadXdppObjects loads xdpp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*xdppObjects
//	*xdppPrograms
//	*xdppMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXdppObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXdpp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xdppSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdppSpecs struct {
	xdppProgramSpecs
	xdppMapSpecs
}

// xdppSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdppProgramSpecs struct {
	MatchPackets *ebpf.ProgramSpec `ebpf:"match_packets"`
}

// xdppMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdppMapSpecs struct {
	PacketBuffer *ebpf.MapSpec `ebpf:"packet_buffer"`
	PacketKeys   *ebpf.MapSpec `ebpf:"packet_keys"`
}

// xdppObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXdppObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdppObjects struct {
	xdppPrograms
	xdppMaps
}

func (o *xdppObjects) Close() error {
	return _XdppClose(
		&o.xdppPrograms,
		&o.xdppMaps,
	)
}

// xdppMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXdppObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdppMaps struct {
	PacketBuffer *ebpf.Map `ebpf:"packet_buffer"`
	PacketKeys   *ebpf.Map `ebpf:"packet_keys"`
}

func (m *xdppMaps) Close() error {
	return _XdppClose(
		m.PacketBuffer,
		m.PacketKeys,
	)
}

// xdppPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXdppObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdppPrograms struct {
	MatchPackets *ebpf.Program `ebpf:"match_packets"`
}

func (p *xdppPrograms) Close() error {
	return _XdppClose(
		p.MatchPackets,
	)
}

func _XdppClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed xdpp_bpfel.o
var _XdppBytes []byte
