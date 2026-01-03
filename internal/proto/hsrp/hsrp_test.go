package hsrp

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftHSRPState(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	vip := net.ParseIP("192.168.1.1")
	priority := uint8(255)
	state := uint8(16)
	group := uint8(1)

	packet, err := CraftHSRPState(srcMAC, vip, priority, state, group)
	if err != nil {
		t.Fatalf("Failed to craft HSRP: %v", err)
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("No Ethernet layer")
	}

	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("No IPv4 layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)
	if !ip.SrcIP.Equal(vip.To4()) {
		t.Errorf("Expected SrcIP %v, got %v", vip, ip.SrcIP)
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("No UDP layer")
	}
	udp, _ := udpLayer.(*layers.UDP)

	payload := udp.Payload
	if len(payload) != 20 {
		t.Errorf("Expected payload len 20, got %d", len(payload))
	}
	t.Logf("Payload: %s", hex.EncodeToString(payload))

	if payload[2] != 16 {
		t.Errorf("Expected state 16, got %d", payload[2])
	}
	if payload[5] != 255 {
		t.Errorf("Expected priority 255, got %d", payload[5])
	}
	if payload[6] != 1 {
		t.Errorf("Expected group 1, got %d", payload[6])
	}
}
