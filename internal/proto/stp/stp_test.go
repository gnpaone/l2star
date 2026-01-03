package stp

import (
	"encoding/hex"
	"net"
	"testing"
)

func TestCraftRootClaimBPDU(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	packet, err := CraftRootClaimBPDU(mac)
	if err != nil {
		t.Fatalf("Failed to craft BPDU: %v", err)
	}

	if len(packet) < 52 {
		t.Errorf("Packet too short: %d bytes", len(packet))
	}

	expectedDst := "0180c2000000"
	dst := hex.EncodeToString(packet[0:6])
	if dst != expectedDst {
		t.Errorf("Expected DstMAC %s, got %s", expectedDst, dst)
	}

	rootIDOffset := 14 + 3 + 2 + 1 + 1 + 1
	rootID := packet[rootIDOffset : rootIDOffset+8]

	if rootID[0] != 0x00 || rootID[1] != 0x00 {
		t.Errorf("Expected Root Priority 0, got %x%x", rootID[0], rootID[1])
	}
}

func TestCraftTCNBPDU(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	packet, err := CraftTCNBPDU(mac)
	if err != nil {
		t.Fatalf("Failed to craft TCN: %v", err)
	}

	if packet[14] != 0x42 || packet[15] != 0x42 {
		t.Errorf("Wrong LLC for STP. Got %x%x", packet[14], packet[15])
	}
	
	if packet[20] != 0x80 {
		t.Errorf("Expected TCN Type 0x80, got %x", packet[20])
	}
}
