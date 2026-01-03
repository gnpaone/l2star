package dtp

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CraftDTPDesirablePacket creates a DTP packet asking to be a trunk (Dynamic Desirable)
func CraftDTPDesirablePacket(srcMAC net.HardwareAddr) ([]byte, error) {
	return craftDTPPacket(srcMAC, 0x03)
}

// CraftDTPTrunkPacket creates a DTP packet forcing trunk mode (Trunk / On)
func CraftDTPTrunkPacket(srcMAC net.HardwareAddr) ([]byte, error) {
	return craftDTPPacket(srcMAC, 0x81)
}

// CraftDTPAutoPacket creates a DTP packet requesting trunk if neighbor asks (Dynamic Auto)
func CraftDTPAutoPacket(srcMAC net.HardwareAddr) ([]byte, error) {
	return craftDTPPacket(srcMAC, 0x04)
}

func craftDTPPacket(srcMAC net.HardwareAddr, status byte) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc},
		EthernetType: layers.EthernetTypeLLC,
	}

	llc := layers.LLC{
		DSAP:    0xaa,
		SSAP:    0xaa,
		Control: 0x03,
	}

	dtpLayer := &CustomDTPLayer{
		Domain: "trunk",
		Status: status,
		Type:   0xa0,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &llc, dtpLayer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type CustomDTPLayer struct {
	layers.BaseLayer
	Domain string
	Status byte
	Type   byte
}

var LayerTypeCustomDTP = gopacket.RegisterLayerType(2004, gopacket.LayerTypeMetadata{Name: "CustomDTP", Decoder: gopacket.DecodeFunc(nil)})

func (d *CustomDTPLayer) LayerType() gopacket.LayerType {
	return LayerTypeCustomDTP
}

func (d *CustomDTPLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	domainBytes := []byte(d.Domain)

	length := 5 + 1
	length += 4 + len(domainBytes)
	length += 5
	length += 5

	bytes, err := b.PrependBytes(length)
	if err != nil {
		return err
	}

	bytes[0] = 0x00
	bytes[1] = 0x00
	bytes[2] = 0x0c
	bytes[3] = 0x20
	bytes[4] = 0x04
	bytes[5] = 0x01

	offset := 6
	writeTLV := func(t uint16, v []byte) {
		binary.BigEndian.PutUint16(bytes[offset:], t)
		binary.BigEndian.PutUint16(bytes[offset+2:], uint16(4+len(v)))
		copy(bytes[offset+4:], v)
		offset += 4 + len(v)
	}

	writeTLV(0x0001, domainBytes)
	writeTLV(0x0002, []byte{d.Status})
	writeTLV(0x0003, []byte{d.Type})

	return nil
}
