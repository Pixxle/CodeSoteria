package agents

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

// Agent is the interface every security scanner agent implements.
type Agent interface {
	// Name returns the agent identifier (e.g., "SAST", "DEPS").
	Name() string

	// Run executes the agent's scan on the given target path.
	// Returns raw findings.
	Run(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error)
}

// toolAvailable checks if a CLI tool is on PATH.
func toolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runTool runs a CLI tool and returns its combined output.
func runTool(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	// Many security tools exit non-zero when findings exist — don't treat as error.
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return "", fmt.Errorf("run %s: %w", name, err)
		}
	}
	return string(out), nil
}

// fingerprint creates a stable hash for deduplication.
func fingerprint(agent, filePath, title string, lineStart int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", agent, filePath, title, lineStart)))
	return fmt.Sprintf("%x", h[:12])
}

// parseJSONFindings is a placeholder for tool-specific JSON parsing.
// Each agent implements its own parser.

// AllAgents returns all available scanner agents.
func AllAgents() []Agent {
	return []Agent{
		NewSASTAgent(),
		NewDepsAgent(),
		NewSecretsAgent(),
		NewConfigAgent(),
	}
}

// trimOutput truncates long outputs to avoid memory issues.
func trimOutput(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n") + fmt.Sprintf("\n... (%d more lines)", len(lines)-maxLines)
}
