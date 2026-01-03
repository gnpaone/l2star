package main

import (
	"fmt"
	"os"

	"github.com/gnpaone/l2star/internal/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// Check for root
	// Check for root
	if os.Geteuid() != 0 {
		fmt.Println("Error: L2-Star requires root privileges for packet manipulation.")
		fmt.Println("Please run with sudo.")
		os.Exit(1)
	}

	p := tea.NewProgram(ui.InitialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
