package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

// Step represents a named unit of work in the progress bar.
type Step struct {
	Name string
	Run  func() error
}

type stepDoneMsg struct{}
type stepErrMsg struct{ err error }

// Model drives a progress bar through a list of sequential steps.
type Model struct {
	steps    []Step
	current  int
	progress progress.Model
	done     bool
	err      error
	width    int
}

// New creates a Model for the given steps.
func New(steps []Step) Model {
	p := progress.New(progress.WithDefaultGradient())
	return Model{
		steps:    steps,
		progress: p,
	}
}

func (m Model) Init() tea.Cmd {
	return m.runCurrentStep()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.progress.Width = msg.Width - 4
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case stepDoneMsg:
		m.current++
		if m.current >= len(m.steps) {
			m.done = true
			return m, tea.Quit
		}
		cmds := []tea.Cmd{
			m.progress.SetPercent(float64(m.current) / float64(len(m.steps))),
			m.runCurrentStep(),
		}
		return m, tea.Batch(cmds...)

	case stepErrMsg:
		m.err = msg.err
		return m, tea.Quit

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	if m.err != nil {
		return fmt.Sprintf("  Error: %v\n", m.err)
	}
	if m.done {
		return fmt.Sprintf("  [%d/%d] Done.\n", len(m.steps), len(m.steps))
	}
	label := m.steps[m.current].Name
	return fmt.Sprintf("  [%d/%d] %s\n  %s\n", m.current+1, len(m.steps), label, m.progress.View())
}

func (m Model) runCurrentStep() tea.Cmd {
	step := m.steps[m.current]
	return func() tea.Msg {
		if err := step.Run(); err != nil {
			return stepErrMsg{err: err}
		}
		return stepDoneMsg{}
	}
}

// Err returns any error that occurred during step execution.
func (m Model) Err() error {
	return m.err
}
