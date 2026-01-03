package dtp

import (
	"net"
	"testing"
)

// CraftDTPDesirablePacket creates a DTP packet asking to be a trunk (Dynamic Desirable)
func TestCraftDTPDesirablePacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	packet, err := CraftDTPDesirablePacket(mac)
	if err != nil {
		t.Fatalf("Failed to craft DTP packet: %v", err)
	}

	verifyDTPPacket(t, packet, 0x03)
}

func TestCraftDTPTrunkPacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	packet, err := CraftDTPTrunkPacket(mac)
	if err != nil {
		t.Fatalf("Failed to craft DTP packet: %v", err)
	}

	verifyDTPPacket(t, packet, 0x81)
}

func TestCraftDTPAutoPacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	packet, err := CraftDTPAutoPacket(mac)
	if err != nil {
		t.Fatalf("Failed to craft DTP packet: %v", err)
	}

	verifyDTPPacket(t, packet, 0x04)
}

func verifyDTPPacket(t *testing.T, packet []byte, expectedStatus byte) {
	snap := packet[17:22]
	if snap[3] != 0x20 || snap[4] != 0x04 {
		t.Errorf("Wrong DTP Protocol ID. Got %x%x", snap[3], snap[4])
	}

	found := false
	for i := 22; i < len(packet)-4; i++ {
		if packet[i] == 0x00 && packet[i+1] == 0x02 {
			if packet[i+4] == expectedStatus {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("Did not find expected status 0x%x in packet", expectedStatus)
	}
}
