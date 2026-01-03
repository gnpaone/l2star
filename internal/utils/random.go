package utils

import (
	"crypto/rand"
	"fmt"
	"net"
)

// RandomMAC generates a random MAC address
func RandomMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	buf[0] = (buf[0] & 0xfe) | 0x02
	return net.HardwareAddr(buf), nil
}

// RandomDeviceID generates a random device ID string (e.g. Router-1234)
func RandomDeviceID(prefix string) string {
	b := make([]byte, 2)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}
