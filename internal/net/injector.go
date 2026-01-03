package net

import (
	"fmt"
	"time"

	"github.com/gnpaone/l2star/internal/core"

	"github.com/google/gopacket/pcap"
)

// ListInterfaces returns valid network interfaces for injection
func ListInterfaces() ([]core.Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var interfaces []core.Interface
	for _, dev := range devs {
		var ips []string
		for _, addr := range dev.Addresses {
			ips = append(ips, addr.IP.String())
		}

		interfaces = append(interfaces, core.Interface{
			Name:        dev.Name,
			Description: dev.Description,
			IPs:         ips,
		})
	}
	return interfaces, nil
}

// StartAttack begins injecting packets on the specified interface
func StartAttack(cfg core.AttackConfig) error {
	handle, err := pcap.OpenLive(cfg.InterfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device: %v", err)
	}
	defer handle.Close()

	if cfg.Frequency == 0 {
		cfg.Frequency = 1 * time.Second
	}

	ticker := time.NewTicker(cfg.Frequency)
	defer ticker.Stop()

	for {
		select {
		case <-cfg.StopChan:
			return nil
		case <-ticker.C:
			var packet []byte
			var err error

			if cfg.Generator != nil {
				packet, err = cfg.Generator()
				if err != nil {
					continue
				}
			} else {
				packet = cfg.StaticPacket
			}

			if len(packet) > 0 {
				if err := handle.WritePacketData(packet); err != nil {
					// Ignore error to keep UI clean? TODO: Show the error somewhere
				}
			}
		}
	}
}
