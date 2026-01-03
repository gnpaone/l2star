package core

import (
	"time"
)

// Interface represents a network interface available for attacks
type Interface struct {
	Name        string
	Description string
	MAC         string
	IPs         []string
}

// PacketGenerator is a function that returns a new packet byte slice or an error
type PacketGenerator func() ([]byte, error)

// AttackConfig configuration for an attack
type AttackConfig struct {
	InterfaceName string
	Generator    PacketGenerator
	StaticPacket []byte
	Frequency    time.Duration
	StopChan     chan struct{}
}
