package cdp

import (
	"net"
	"strings"
	"testing"
)

// CraftCDPFloodPacket creates a random CDP packet for flooding
func TestCraftCDPFloodPacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	deviceID := "TestRouter"
	portID := "GigabitEthernet0/1"

	packet, err := CraftCDPFloodPacket(mac, deviceID, portID)
	if err != nil {
		t.Fatalf("Failed to craft CDP packet: %v", err)
	}

	verifyCDPPacket(t, packet, deviceID, portID)
}

func TestCraftCDPNeighborAnnouncement(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	deviceID := "CoreSwitch"
	portID := "GigabitEthernet1/0/1"
	platform := "cisco WS-C3750G-24TS"
	software := "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 12.2(55)SE1"
	capabilities := uint32(0x00000028) // Switch | IGMP
	nativeVLAN := uint16(10)

	packet, err := CraftCDPNeighborAnnouncement(mac, deviceID, portID, platform, software, capabilities, nativeVLAN)
	if err != nil {
		t.Fatalf("Failed to craft CDP packet: %v", err)
	}

	verifyCDPPacket(t, packet, deviceID, portID)

	if len(packet) < 100 {
		t.Errorf("Packet seems too short for full announcement: %d", len(packet))
	}
}

func TestCraftCDPDoS(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	packet1, err := CraftCDPDoS(mac)
	if err != nil {
		t.Fatalf("Failed to craft DoS packet 1: %v", err)
	}
	packet2, err := CraftCDPDoS(mac)
	if err != nil {
		t.Fatalf("Failed to craft DoS packet 2: %v", err)
	}

	if string(packet1) == string(packet2) {
		t.Errorf("DoS packets should be random and different")
	}
}

func verifyCDPPacket(t *testing.T, packet []byte, deviceID, portID string) {
	if len(packet) < 30 {
		t.Errorf("Packet too short: %d", len(packet))
	}

	expectedDstBytes := []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}
	for i, b := range expectedDstBytes {
		if packet[i] != b {
			t.Errorf("Byte %d of DstMAC mismatch. Got %x, want %x", i, packet[i], b)
		}
	}

	packetStr := string(packet)
	if !strings.Contains(packetStr, deviceID) {
		t.Errorf("Packet does not contain deviceID %s", deviceID)
	}
	if !strings.Contains(packetStr, portID) {
		t.Errorf("Packet does not contain portID %s", portID)
	}
}
