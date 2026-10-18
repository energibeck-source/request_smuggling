package theory

import (
	"fmt"
	"log"
	"os"
	//"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4")).
			MarginBottom(1)

	topicStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#3C3C3C")).
			Padding(0, 1).
			MarginRight(1)

	selectedTopicStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(lipgloss.Color("#7D56F4")).
				Padding(0, 1).
				MarginRight(1)

	contentStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#D4D4D4")).
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4"))

	codeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Background(lipgloss.Color("#1E1E1E")).
			Padding(0, 1).
			Margin(1, 0)

	backStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Italic(true).
			MarginTop(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00AAFF")).
			Bold(true).
			MarginTop(1).
			MarginBottom(1)
)

type Topic struct {
	Name    string
	Content string
}

func parseMarkdown(filename string) ([]Topic, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	topics := []Topic{}
	currentTopic := Topic{}
	currentContent := []string{}
	inCodeBlock := false

	for _, line := range lines {
		if strings.HasPrefix(line, "## ") && !inCodeBlock {
			if currentTopic.Name != "" {
				currentTopic.Content = strings.TrimSpace(strings.Join(currentContent, "\n"))
				topics = append(topics, currentTopic)
				currentContent = []string{}
			}
			currentTopic.Name = strings.TrimPrefix(line, "## ")
		} else if strings.HasPrefix(line, "```") {
			inCodeBlock = !inCodeBlock
			currentContent = append(currentContent, line)
		} else {
			currentContent = append(currentContent, line)
		}
	}

	if currentTopic.Name != "" {
		currentTopic.Content = strings.TrimSpace(strings.Join(currentContent, "\n"))
		topics = append(topics, currentTopic)
	}

	return topics, nil
}

func formatContent(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var code []string
	inCodeBlock := false

	flush := func() {
		if len(code) > 0 {
			result = append(result, codeStyle.Render(strings.Join(code, "\n")))
			code = code[:0]
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "```") {
			if inCodeBlock {
				flush()
			}
			inCodeBlock = !inCodeBlock
			continue
		}

		if inCodeBlock {
			code = append(code, line)
		} else {
			result = append(result, line)
		}
	}
	flush()

	return strings.Join(result, "\n")
}

type model struct {
	topics        []Topic
	currentView   string
	selectedIdx   int
	cursor        int
	width, height int
	viewport      viewport.Model
	ready         bool
}

func (m *model) loadTopicContent() {
	m.viewport.SetContent(formatContent(m.topics[m.selectedIdx].Content))
	m.viewport.GotoTop()
}

func newModel() (model, error) {

	paths := []string{
		"theory.md",
		"../theory.md",
		"./theory/theory.md",
		"../theory/theory.md",
	}

	var topics []Topic
	var err error

	for _, p := range paths {
		topics, err = parseMarkdown(p)
		if err == nil && len(topics) > 0 {
			break
		}
	}

	if err != nil || len(topics) == 0 {
		return model{}, fmt.Errorf("theory.md file not found")
	}

	return model{
		topics:      topics,
		currentView: "list",
		cursor:      0,
	}, nil
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		verticalMargin := lipgloss.Height(m.headerView()) + lipgloss.Height(m.footerView()) + 2
		vpWidth := msg.Width - 4
		vpHeight := msg.Height - verticalMargin
		if vpWidth < 1 {
			vpWidth = 1
		}
		if vpHeight < 1 {
			vpHeight = 1
		}
		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.ready = true
			m.loadTopicContent()
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "up", "k":
			if m.currentView == "list" && m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.currentView == "list" && m.cursor < len(m.topics)-1 {
				m.cursor++
			}

		case "enter", " ":
			if m.currentView == "list" {
				m.selectedIdx = m.cursor
				m.currentView = "content"
				if m.ready {
					m.loadTopicContent()
				}
			} else {
				m.currentView = "list"
			}

		case "esc", "h", "left":
			if m.currentView == "content" {
				m.currentView = "list"
			}

		case "n":
			if m.currentView == "content" && m.selectedIdx < len(m.topics)-1 {
				m.selectedIdx++
				if m.ready {
					m.loadTopicContent()
				}
			}

		case "p":
			if m.currentView == "content" && m.selectedIdx > 0 {
				m.selectedIdx--
				if m.ready {
					m.loadTopicContent()
				}
			}
		}
	}

	if m.currentView == "content" && m.ready {
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) headerView() string {
	name := ""
	if m.selectedIdx < len(m.topics) {
		name = m.topics[m.selectedIdx].Name
	}
	return titleStyle.Render(fmt.Sprintf("📖 %s", name))
}

func (m model) footerView() string {
	scroll := 0.0
	if m.ready {
		scroll = m.viewport.ScrollPercent() * 100
	}
	return backStyle.Render(fmt.Sprintf("←/Esc - back • n/p - next/prev • ↑/↓/wheel - scroll • q - exit  (%3.0f%%)", scroll))
}

func (m model) View() string {
	if m.currentView == "list" {
		return m.renderList()
	}
	return m.renderContent()
}

func (m model) renderList() string {
	var s strings.Builder

	s.WriteString(titleStyle.Render("🔐 HTTP/2 Request Smuggling"))
	s.WriteString(subtitleStyle.Render("Theory"))
	s.WriteString("\n\n")

	for i, topic := range m.topics {
		if i == m.cursor {
			s.WriteString(selectedTopicStyle.Render("→ " + topic.Name))
		} else {
			s.WriteString(topicStyle.Render("  " + topic.Name))
		}
		s.WriteString("\n")
	}

	s.WriteString("\n")
	s.WriteString(backStyle.Render("↑/↓ - navigation • Enter - select • q - exit"))

	return s.String()
}

func (m model) renderContent() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	var s strings.Builder
	s.WriteString(m.headerView())
	s.WriteString("\n\n")
	s.WriteString(contentStyle.Render(m.viewport.View()))
	s.WriteString("\n")
	s.WriteString(m.footerView())

	return s.String()
}

func RunViewer() {

	found := false
	paths := []string{"theory.md", "../theory.md", "./theory/theory.md", "../theory/theory.md"}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			found = true
			break
		}
	}

	if !found {
		fmt.Println("❌ Error: theory.md file not found!")
		fmt.Println("Expected paths:")
		for _, p := range paths {
			fmt.Printf("  - %s\n", p)
		}
		os.Exit(1)
	}

	model, err := newModel()
	if err != nil {
		log.Fatal("Error loading theory:", err)
	}

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
