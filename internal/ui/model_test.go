package ui

import (
	"testing"

	"github.com/gnpaone/l2star/internal/core"

	tea "github.com/charmbracelet/bubbletea"
)

// Mock core interface for testing
var mockInterfaces = []core.Interface{
	{Name: "eth0", Description: "Test Interface", IPs: []string{"192.168.1.1"}},
	{Name: "wlan0", Description: "Wireless", IPs: []string{"10.0.0.1"}},
}

func TestModelInitialState(t *testing.T) {
	m := InitialModel()
	if m.state != StateInterfaceSelect {
		t.Errorf("Expected initial state StateInterfaceSelect, got %v", m.state)
	}
}

func TestNavigationToMain(t *testing.T) {
	m := InitialModel()
	m.interfaces = mockInterfaces
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	updatedModel := newM.(Model)

	if updatedModel.state != StateMain {
		t.Errorf("Expected state StateMain after Enter, got %v", updatedModel.state)
	}

	if updatedModel.activeInterface != "eth0" {
		t.Errorf("Expected active interface 'eth0', got '%s'", updatedModel.activeInterface)
	}
}

func TestNavigationBackWithEsc(t *testing.T) {
	m := InitialModel()
	m.interfaces = mockInterfaces
	m.state = StateMain
	m.activeInterface = "eth0"

	msg := tea.KeyMsg{Type: tea.KeyEsc}
	newM, _ := m.Update(msg)
	updatedModel := newM.(Model)

	if updatedModel.state != StateInterfaceSelect {
		t.Errorf("Expected state StateInterfaceSelect after Esc, got %v", updatedModel.state)
	}
}

func TestTabNavigation(t *testing.T) {
	m := InitialModel()
	m.state = StateMain
	m.tabs = []string{"STP", "CDP", "DTP"}
	m.activeTab = 0

	msg := tea.KeyMsg{Type: tea.KeyTab}
	newM, _ := m.Update(msg)
	updatedModel := newM.(Model)

	if updatedModel.activeTab != 1 {
		t.Errorf("Expected active tab 1 (CDP) after Tab, got %d", updatedModel.activeTab)
	}
}
