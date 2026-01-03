package arp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftARPReply(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.10")

	packet, err := CraftARPReply(srcMAC, dstMAC, srcIP, dstIP)
	if err != nil {
		t.Fatalf("Failed to craft ARP Reply: %v", err)
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		t.Fatal("No ARP layer found")
	}

	arp, _ := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		t.Errorf("Expected OpCode Reply (2), got %d", arp.Operation)
	}

	if !net.IP(arp.SourceProtAddress).Equal(srcIP.To4()) {
		t.Errorf("Source IP mismatch: got %v, want %v", arp.SourceProtAddress, srcIP)
	}
}

func TestCraftARPRequest(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.ParseIP("192.168.1.100")
	targetIP := net.ParseIP("192.168.1.200")

	packet, err := CraftARPRequest(srcMAC, srcIP, targetIP)
	if err != nil {
		t.Fatalf("Failed to craft ARP Request: %v", err)
	}
	
	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		t.Fatal("No ARP layer found")
	}

	arp, _ := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPRequest {
		t.Errorf("Expected OpCode Request (1), got %d", arp.Operation)
	}
}
