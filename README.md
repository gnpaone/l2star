# L2-Star ⭐️

**L2-Star** is a modern, Go-based Terminal User Interface (TUI) tool for performing Layer 2 network attacks. It is designed as a lightweight, maintainable successor to the classic `yersinia` tool, focusing on reliability and ease of use in modern Linux environments.

![L2-Star TUI]()

## 🚀 Features

L2-Star supports targeted attacks on common Layer 2 protocols:

### **STP (Spanning Tree Protocol)**
- **Root Bridge Claiming**: Spoofs a Configuration BPDU with Priority 0 to take over as the Root Bridge, allowing for Man-in-the-Middle (MitM) positioning.
- **TCN Injection**: Inject Topology Change Notifications to force switches to flush their CAM tables, causing traffic flooding and facilitating sniffing.

### **CDP (Cisco Discovery Protocol)**
- **Randomized Flooding (DoS)**: Floods the network with packets containing randomized Device IDs to exhaust switch memory (CDP Neighbor Table overflow).
- **Neighbor Spoofing**: Broadcasts custom CDP announcements acting as a specific high-value device (e.g., Core Switch, VoIP Phone) to manipulate trust relationships or map topology.

### **DTP (Dynamic Trunking Protocol)**
- **Trunk Negotiation (Desirable)**: Injects "Dynamic Desirable" frames to actively negotiate a trunk link with a connected switch port.
- **Trunk Negotiation (Auto)**: Injects "Dynamic Auto" frames to negotiate a trunk if the neighbor is set to Desirable.
- **Force Trunk**: Injects "Trunk (On)" frames to eagerly force a trunk link.

### **ARP (Address Resolution Protocol)**
- **Spoofing (Reply)**: Sends spoofed ARP Replies (Gratuitous or Unsolicited) to poison victim ARP caches, enabling Man-in-the-Middle attacks.
- **Flooding (Request)**: Sends ARP Requests to scan for potential targets or flood the network.

### **LLDP (Link Layer Discovery Protocol)**
- **Neighbor Spoofing**: Broadcasts custom LLDP frames to impersonate a legitimate device (e.g., Switch or Router), masking the attacker's presence.

### **DHCP (Dynamic Host Configuration Protocol)**
- **Starvation**: Floods DHCP Discovery packets with randomized Client MACs to exhaust the server's IP address pool.
- **Rogue Server**: Responds to client requests with malicious DHCP Offers (e.g., assigning a compromised Gateway or DNS).

### **HSRP (Hot Standby Router Protocol)**
- **Active Router Takeover**: Injects HSRP Hello packets with maximum Priority (255) to claim the "Active" state and hijack the Virtual IP (VIP).

## 🛠️ Architecture

Built with a focus on modern Go tooling:
- **UI**: [Bubbletea](https://github.com/charmbracelet/bubbletea) for a beautiful, keyboard-driven TUI.
- **Networking**: [GoPacket](https://github.com/google/gopacket) (libpcap) for raw socket management and packet crafting.
- **Core**: Custom injection engine supporting both static packet injection and high-performance dynamic packet generation.

## 📦 Installation

### Prerequisites
- **Linux** (Root privileges required for raw sockets)
- **libpcap** headers
- **Go 1.21+**

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install libpcap-dev

# Fedora
sudo dnf install libpcap-devel
```

### Build from Source

```bash
git clone https://github.com/gnpaone/l2star.git
cd l2star
go mod tidy
go build -o l2star cmd/l2star/main.go
```

## 🎮 Usage

L2-Star requires root privileges to inject raw packets.

```bash
sudo ./l2star
```

### Controls

- **Interface Selection**:
  - `↑` / `↓` (`k` / `j`): Navigate interfaces.
  - `Enter`: Select interface.

- **Main Dashboard**:
  - `Tab` / `Shift+Tab`: Switch Protocol Tabs (STP, CDP, DTP).
  - `↑` / `↓` (`k` / `j`): Select Attack Type (for protocols with multiple attacks like STP).
  - `Space`: **Start / Stop Attack**.
  - `q` / `Ctrl+C`: Quit.

## ⚠️ Disclaimer

**L2-Star is for educational and authorized security testing purposes only.**
Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
*Developed with Go & Bubbletea.*
