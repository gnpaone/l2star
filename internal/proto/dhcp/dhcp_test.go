package dhcp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftDHCPDiscover(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x00, 0x22, 0x33, 0x44}
	packet, err := CraftDHCPDiscover(srcMAC)
	if err != nil {
		t.Fatalf("Failed to craft DHCP Discover: %v", err)
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	dhcpLayer := pkt.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		t.Fatal("No DHCP layer")
	}
	dhcp, _ := dhcpLayer.(*layers.DHCPv4)
	if dhcp.Operation != layers.DHCPOpRequest {
		t.Errorf("Expected DHCPOpRequest, got %v", dhcp.Operation)
	}
}

func TestCraftDHCPOffer(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x00, 0x22, 0x33, 0x44}
	dstMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	serverIP := net.IPv4(192, 168, 1, 1)
	offeredIP := net.IPv4(192, 168, 1, 100)
	gatewayIP := net.IPv4(192, 168, 1, 1)

	packet, err := CraftDHCPOffer(srcMAC, dstMAC, serverIP, offeredIP, gatewayIP, 12345)
	if err != nil {
		t.Fatalf("Failed to craft DHCP Offer: %v", err)
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	dhcpLayer := pkt.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		t.Fatal("No DHCP layer")
	}
	dhcp, _ := dhcpLayer.(*layers.DHCPv4)
	if dhcp.Operation != layers.DHCPOpReply {
		t.Errorf("Expected Reply, got %v", dhcp.Operation)
	}
	if !dhcp.YourClientIP.Equal(offeredIP.To4()) {
		t.Errorf("Expected offeredIP %v, got %v", offeredIP, dhcp.YourClientIP)
	}
}
