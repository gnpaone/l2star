package hsrp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CraftHSRPState creates an HSRP Hello/Coup packet claiming a state.
func CraftHSRPState(srcMAC net.HardwareAddr, vip net.IP, priority uint8, state uint8, group uint8) ([]byte, error) {
	dstMAC := net.HardwareAddr{0x00, 0x00, 0x0c, 0x07, 0xac, byte(group)}

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      1,
		SrcIP:    vip,
		DstIP:    net.ParseIP("224.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 1985,
		DstPort: 1985,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	payload := make([]byte, 20)
	payload[0] = 0
	payload[1] = 0
	payload[2] = state
	payload[3] = 3
	payload[4] = 10
	payload[5] = priority
	payload[6] = group
	payload[7] = 0
	copy(payload[8:], []byte("cisco\x00\x00\x00"))
	copy(payload[16:], vip.To4())

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
