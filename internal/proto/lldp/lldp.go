package lldp

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type CustomLLDP struct {
	layers.BaseLayer
	TLVs []LLDPTLV
}

type LLDPTLV struct {
	Type   uint8
	Length uint16
	Value  []byte
}

var LayerTypeCustomLLDP = gopacket.RegisterLayerType(
	31337,
	gopacket.LayerTypeMetadata{Name: "CustomLLDP", Decoder: gopacket.DecodeFunc(decodeLLDP)},
)

func (l *CustomLLDP) LayerType() gopacket.LayerType {
	return LayerTypeCustomLLDP
}

func (l *CustomLLDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	for _, tlv := range l.TLVs {
		typeAndLen := (uint16(tlv.Type) << 9) | (tlv.Length & 0x01FF)
		bytes, err := b.AppendBytes(2 + int(tlv.Length))
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(bytes[0:2], typeAndLen)
		copy(bytes[2:], tlv.Value)
	}
	return nil
}

func decodeLLDP(data []byte, p gopacket.PacketBuilder) error {
	return nil
}

func CraftLLDPNeighbor(srcMAC net.HardwareAddr, chassisID, portID, sysName string) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
		EthernetType: layers.EthernetTypeLinkLayerDiscovery,
	}

	const (
		TLVEnd       = 0
		TLVChassisID = 1
		TLVPortID    = 2
		TLVTTL       = 3
		TLVSysName   = 5
	)

	lldp := CustomLLDP{
		TLVs: []LLDPTLV{
			{
				Type:   TLVChassisID,
				Length: uint16(1 + len(chassisID)),
				Value:  append([]byte{7}, []byte(chassisID)...),
			},
			{
				Type:   TLVPortID,
				Length: uint16(1 + len(portID)),
				Value:  append([]byte{7}, []byte(portID)...),
			},
			{
				Type:   TLVTTL,
				Length: 2,
				Value:  []byte{0x00, 0x78},
			},
		},
	}

	if sysName != "" {
		lldp.TLVs = append(lldp.TLVs, LLDPTLV{
			Type:   TLVSysName,
			Length: uint16(len(sysName)),
			Value:  []byte(sysName),
		})
	}

	lldp.TLVs = append(lldp.TLVs, LLDPTLV{
		Type:   TLVEnd,
		Length: 0,
		Value:  []byte{},
	})

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &lldp)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
