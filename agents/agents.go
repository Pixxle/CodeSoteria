// Package agents provides LLM-based security analysis agents.
// Each agent loads a prompt template from /prompts, injects tool results
// and source code, and produces enriched security findings.
package agents

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

//go:embed prompts/*.md.tmpl
var promptFS embed.FS

// SourceFile represents a source file to include in the agent prompt.
type SourceFile struct {
	Path    string
	Content string
}

// ToolInput holds tool result data for template rendering.
type ToolInput struct {
	Name       string
	Status     string
	OutputFile string
	RawOutput  string
}

// AgentInput is the data passed to an agent prompt template.
type AgentInput struct {
	ToolResults []ToolInput
	SourceFiles []SourceFile
}

// AgentResult holds an agent's output after processing.
type AgentResult struct {
	Agent        string
	FindingCount int
	FindingsJSON string
	Findings     []*scanner.RawFinding
}

// ConsolidateInput is the data passed to the consolidation prompt template.
type ConsolidateInput struct {
	AgentResults []AgentResult
}

// RenderPrompt renders an agent's prompt template with the given input.
func RenderPrompt(agentName string, input AgentInput) (string, error) {
	tmplPath := fmt.Sprintf("prompts/%s.md.tmpl", strings.ToLower(agentName))
	tmplContent, err := promptFS.ReadFile(tmplPath)
	if err != nil {
		// Try from disk as fallback (for development)
		diskPath := filepath.Join("agents", "prompts", strings.ToLower(agentName)+".md.tmpl")
		tmplContent, err = os.ReadFile(diskPath)
		if err != nil {
			return "", fmt.Errorf("load prompt template %s: %w", agentName, err)
		}
	}

	tmpl, err := template.New(agentName).Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("parse prompt template %s: %w", agentName, err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return "", fmt.Errorf("execute prompt template %s: %w", agentName, err)
	}

	return buf.String(), nil
}

// RenderConsolidatePrompt renders the consolidation prompt template.
func RenderConsolidatePrompt(input ConsolidateInput) (string, error) {
	tmplPath := "prompts/consolidate.md.tmpl"
	tmplContent, err := promptFS.ReadFile(tmplPath)
	if err != nil {
		diskPath := filepath.Join("agents", "prompts", "consolidate.md.tmpl")
		tmplContent, err = os.ReadFile(diskPath)
		if err != nil {
			return "", fmt.Errorf("load consolidate template: %w", err)
		}
	}

	tmpl, err := template.New("consolidate").Parse(string(tmplContent))
	if err != nil {
		return "", fmt.Errorf("parse consolidate template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, input); err != nil {
		return "", fmt.Errorf("execute consolidate template: %w", err)
	}

	return buf.String(), nil
}

// BuildAgentInput constructs the AgentInput for a given agent from tool results.
func BuildAgentInput(agentName string, toolResults []scanner.ToolResult, sourceFiles []SourceFile) (AgentInput, error) {
	filtered := scanner.ToolResultsForAgent(toolResults, agentName)

	var inputs []ToolInput
	for _, tr := range filtered {
		ti := ToolInput{
			Name:       tr.Name,
			Status:     tr.Status,
			OutputFile: tr.OutputFile,
		}
		if tr.OutputFile != "" {
			raw, err := scanner.ReadToolOutput(tr)
			if err != nil {
				ti.RawOutput = fmt.Sprintf("Error reading output: %v", err)
			} else {
				ti.RawOutput = raw
			}
		}
		inputs = append(inputs, ti)
	}

	return AgentInput{
		ToolResults: inputs,
		SourceFiles: sourceFiles,
	}, nil
}

// ParseAgentResponse parses the JSON findings array from an LLM agent response.
func ParseAgentResponse(agentName string, response string) ([]*scanner.RawFinding, error) {
	// Extract JSON array from response (the LLM may include markdown fences)
	response = extractJSON(response)

	var findings []*scanner.RawFinding
	if err := json.Unmarshal([]byte(response), &findings); err != nil {
		// Try wrapping in array if it's a single object
		var single scanner.RawFinding
		if err2 := json.Unmarshal([]byte(response), &single); err2 == nil {
			return []*scanner.RawFinding{&single}, nil
		}
		return nil, fmt.Errorf("parse %s response: %w\nResponse: %.500s", agentName, err, response)
	}

	// Set agent field if not set
	for _, f := range findings {
		if f.Agent == "" {
			f.Agent = agentName
		}
		if f.Fingerprint == "" {
			f.Fingerprint = GenerateFingerprint(f.Agent, f.FilePath, f.Title, f.LineStart)
		}
	}

	return findings, nil
}

// SavePromptToFile writes a rendered prompt to disk for debugging/audit.
func SavePromptToFile(outputDir, agentName, prompt string) error {
	promptDir := filepath.Join(outputDir, "prompts")
	os.MkdirAll(promptDir, 0755)
	path := filepath.Join(promptDir, strings.ToLower(agentName)+"-prompt.md")
	return os.WriteFile(path, []byte(prompt), 0644)
}

// SaveAgentResult writes agent findings to disk.
func SaveAgentResult(outputDir, agentName string, findings []*scanner.RawFinding) error {
	findingsDir := filepath.Join(outputDir, "findings")
	os.MkdirAll(findingsDir, 0755)

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(findingsDir, strings.ToLower(agentName)+".json")
	return os.WriteFile(path, data, 0644)
}

// extractJSON strips markdown code fences and finds the JSON array/object.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)

	// Remove markdown code fences
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
	}
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSuffix(s, "```")
	}
	s = strings.TrimSpace(s)

	// Find first [ or { and last ] or }
	start := strings.IndexAny(s, "[{")
	if start < 0 {
		return s
	}

	opener := s[start]
	var closer byte
	if opener == '[' {
		closer = ']'
	} else {
		closer = '}'
	}

	end := strings.LastIndexByte(s, closer)
	if end < start {
		return s
	}

	return s[start : end+1]
}

// GenerateFingerprint creates a stable hash for deduplication.
func GenerateFingerprint(agent, filePath, title string, lineStart int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", agent, filePath, title, lineStart)))
	return fmt.Sprintf("%x", h[:12])
}

// AgentNames returns the ordered list of all agent names.
func AgentNames() []string {
	return []string{"SAST", "DEPS", "SECRETS", "CONFIG", "AUTH", "CRYPTO", "API", "DATA"}
}

// ToolAgentNames returns agent names that have external tools.
func ToolAgentNames() []string {
	return []string{"SAST", "DEPS", "SECRETS", "CONFIG"}
}

// LLMOnlyAgentNames returns agent names that are LLM-only (no tools).
func LLMOnlyAgentNames() []string {
	return []string{"AUTH", "CRYPTO", "API", "DATA"}
}
