package ui

import "github.com/charmbracelet/lipgloss"

var (
	ColorPrimary   = lipgloss.Color("#7D56F4")
	ColorSecondary = lipgloss.Color("#EE6FF8")
	ColorText      = lipgloss.Color("#FAFAFA")
	ColorSubText   = lipgloss.Color("#A1A1A1")
	ColorDanger    = lipgloss.Color("#FF4444")
	ColorSuccess   = lipgloss.Color("#00FF88")

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Padding(0, 1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorPrimary)

	TabStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(ColorSubText)

	ActiveTabStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(ColorText).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorSecondary)

	ButtonStyle = lipgloss.NewStyle().
			Foreground(ColorText).
			Background(ColorPrimary).
			Padding(0, 2).
			MarginTop(1)

	DangerButtonStyle = ButtonStyle.Copy().
				Background(ColorDanger)

	LogBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSubText).
			Padding(0, 1).
			Height(10)
)
