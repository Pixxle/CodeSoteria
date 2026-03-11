package agents

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// LLMClient defines the interface for calling an LLM to process agent prompts.
type LLMClient interface {
	// Complete sends a prompt to the LLM and returns the response text.
	Complete(systemPrompt, userPrompt string) (string, error)
}

// Valid model shorthand names.
var validModels = map[string]bool{
	"opus":   true,
	"sonnet": true,
	"haiku":  true,
}

// ClaudeCodeClient invokes the `claude` CLI for LLM completions.
type ClaudeCodeClient struct {
	Model string // shorthand: "opus", "sonnet", or "haiku"
}

// NewClaudeCodeClient creates a client that shells out to the claude CLI.
// Model must be "opus", "sonnet", or "haiku". Defaults to "sonnet" if empty or invalid.
func NewClaudeCodeClient(model string) *ClaudeCodeClient {
	model = strings.ToLower(strings.TrimSpace(model))
	if !validModels[model] {
		model = "sonnet"
	}
	return &ClaudeCodeClient{Model: model}
}

func (c *ClaudeCodeClient) Complete(systemPrompt, userPrompt string) (string, error) {
	// Build the combined prompt — system prompt as context, user prompt as the task
	fullPrompt := systemPrompt + "\n\n" + userPrompt

	args := []string{
		"--print",   // non-interactive, print response and exit
		"--dangerously-skip-permissions", // no permission prompts in automated mode
	}

	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}

	// Pass the prompt via stdin using --prompt flag with "-" for stdin
	args = append(args, "--prompt", "-")

	cmd := exec.Command("claude", args...)
	cmd.Stdin = strings.NewReader(fullPrompt)
	cmd.Stderr = os.Stderr

	log.Printf("[LLM] Invoking claude CLI (model=%s, prompt=%d bytes)", c.Model, len(fullPrompt))

	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("claude CLI exited %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return "", fmt.Errorf("claude CLI: %w", err)
	}

	response := strings.TrimSpace(string(out))
	if response == "" {
		return "", fmt.Errorf("empty response from claude CLI")
	}

	log.Printf("[LLM] Response received (%d bytes)", len(response))
	return response, nil
}

// NoOpLLMClient is a placeholder that returns empty findings (for tool-only mode).
type NoOpLLMClient struct{}

func (c *NoOpLLMClient) Complete(systemPrompt, userPrompt string) (string, error) {
	return "[]", nil
}
