package lldp

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCraftLLDPNeighbor(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	chassisID := "TestSwitch"
	portID := "Gig0/1"
	sysName := "MySystem"

	packet, err := CraftLLDPNeighbor(srcMAC, chassisID, portID, sysName)
	if err != nil {
		t.Fatalf("Failed to craft LLDP: %v", err)
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("No Ethernet layer")
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	payload := eth.Payload
	if len(payload) == 0 {
		t.Fatal("Empty payload")
	}

	t.Logf("Payload: %s", hex.EncodeToString(payload))

	if payload[0] != 0x02 || payload[1] != 0x0B {
		t.Errorf("Expected Chassis TLV header 0x020B, got 0x%02x%02x", payload[0], payload[1])
	}
}
