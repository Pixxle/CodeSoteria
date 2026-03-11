package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ToolRunner executes external security tools and writes raw results to files.
// It does NOT interpret or enrich results — that is the agents' job.
type ToolRunner struct {
	OutputDir string // base output directory for raw tool results
}

// NewToolRunner creates a ToolRunner that writes to the given output directory.
func NewToolRunner(outputDir string) *ToolRunner {
	return &ToolRunner{OutputDir: outputDir}
}

// ToolResult records what happened when a tool was executed.
type ToolResult struct {
	Name       string `json:"name"`
	Agent      string `json:"agent"`
	Status     string `json:"status"` // ran_successfully, failed, skipped, unavailable
	OutputFile string `json:"output_file,omitempty"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RunAllTools executes all applicable tools against the target path in parallel.
// Returns a manifest of what ran, what produced output, and where files are.
func (tr *ToolRunner) RunAllTools(ctx context.Context, targetPath string) ([]ToolResult, error) {
	var results []ToolResult
	var mu sync.Mutex

	// Define all tools grouped by agent domain
	tools := tr.buildToolList(targetPath)

	var wg sync.WaitGroup
	// Limit concurrency
	sem := make(chan struct{}, 4)

	for _, t := range tools {
		wg.Add(1)
		go func(td toolDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := tr.runTool(ctx, td)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// Write the manifest
	manifestPath := filepath.Join(tr.OutputDir, "tool-manifest.json")
	data, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(manifestPath, data, 0644)

	return results, nil
}

// toolDef defines a single tool invocation.
type toolDef struct {
	Name       string
	Agent      string
	Binary     string
	Args       []string
	OutputFile string // relative to OutputDir
}

func (tr *ToolRunner) buildToolList(targetPath string) []toolDef {
	raw := filepath.Join(tr.OutputDir, "raw")
	os.MkdirAll(raw, 0755)

	semgrepOut := filepath.Join(raw, "semgrep-output.json")
	banditOut := filepath.Join(raw, "bandit-output.json")
	gosecOut := filepath.Join(raw, "gosec-output.json")
	osvOut := filepath.Join(raw, "osv-scanner-output.json")
	grypeOut := filepath.Join(raw, "grype-output.json")
	trivyOut := filepath.Join(raw, "trivy-output.json")
	gitleaksOut := filepath.Join(raw, "gitleaks-output.json")
	trufflehogOut := filepath.Join(raw, "trufflehog-output.json")
	checkovOut := filepath.Join(raw, "checkov-output.json")

	return []toolDef{
		// SAST tools
		{Name: "semgrep", Agent: "SAST", Binary: "semgrep",
			Args:       []string{"scan", "--config=auto", "--json", "--output", semgrepOut, targetPath},
			OutputFile: semgrepOut},
		{Name: "bandit", Agent: "SAST", Binary: "bandit",
			Args:       []string{"-r", targetPath, "-f", "json", "-o", banditOut, "--severity-level", "medium"},
			OutputFile: banditOut},
		{Name: "gosec", Agent: "SAST", Binary: "gosec",
			Args:       []string{"-fmt=json", "-out=" + gosecOut, targetPath + "/..."},
			OutputFile: gosecOut},

		// DEPS tools
		{Name: "osv-scanner", Agent: "DEPS", Binary: "osv-scanner",
			Args:       []string{"scan", "--format", "json", "--output", osvOut, "-r", targetPath},
			OutputFile: osvOut},
		{Name: "grype", Agent: "DEPS", Binary: "grype",
			Args:       []string{"dir:" + targetPath, "-o", "json", "--file", grypeOut, "--quiet"},
			OutputFile: grypeOut},
		{Name: "trivy", Agent: "DEPS", Binary: "trivy",
			Args:       []string{"fs", "--format", "json", "--output", trivyOut, "--quiet", targetPath},
			OutputFile: trivyOut},

		// SECRETS tools
		{Name: "gitleaks", Agent: "SECRETS", Binary: "gitleaks",
			Args:       []string{"detect", "--source", targetPath, "--report-format", "json", "--report-path", gitleaksOut, "--no-banner"},
			OutputFile: gitleaksOut},
		{Name: "trufflehog", Agent: "SECRETS", Binary: "trufflehog",
			Args:       []string{"filesystem", targetPath, "--json", "--no-verification", "--no-update"},
			OutputFile: trufflehogOut},

		// CONFIG tools
		{Name: "checkov", Agent: "CONFIG", Binary: "checkov",
			Args:       []string{"-d", targetPath, "--output", "json", "--quiet", "--compact", "-o", checkovOut},
			OutputFile: checkovOut},
	}
}

func (tr *ToolRunner) runTool(ctx context.Context, td toolDef) ToolResult {
	result := ToolResult{
		Name:  td.Name,
		Agent: td.Agent,
	}

	// Check availability
	path, err := exec.LookPath(td.Binary)
	if err != nil {
		result.Status = "unavailable"
		log.Printf("[TOOL] %s: unavailable", td.Name)
		return result
	}
	result.Version = getToolVersion(td.Binary)

	log.Printf("[TOOL] %s: running...", td.Name)

	cmd := exec.CommandContext(ctx, path, td.Args...)

	// For trufflehog, capture stdout to file (it writes to stdout)
	if td.Name == "trufflehog" {
		outFile, err := os.Create(td.OutputFile)
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()
			return result
		}
		cmd.Stdout = outFile
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		outFile.Close()
		if err != nil {
			// Many tools exit non-zero when findings exist
			if _, ok := err.(*exec.ExitError); !ok {
				result.Status = "failed"
				result.Error = err.Error()
				return result
			}
		}
	} else {
		// For checkov, redirect stdout to file since -o flag means output format not file
		if td.Name == "checkov" {
			// Fix: checkov uses --output for format, --output-file for file
			cmd = exec.CommandContext(ctx, path, "-d", cmd.Args[2], "--output", "json", "--quiet", "--compact")
			outFile, err := os.Create(td.OutputFile)
			if err != nil {
				result.Status = "failed"
				result.Error = err.Error()
				return result
			}
			cmd.Stdout = outFile
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			outFile.Close()
			if err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					result.Status = "failed"
					result.Error = err.Error()
					return result
				}
			}
		} else {
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					result.Status = "failed"
					result.Error = err.Error()
					return result
				}
			}
		}
	}

	// Verify output file exists and has content
	info, err := os.Stat(td.OutputFile)
	if err != nil || info.Size() == 0 {
		result.Status = "ran_successfully"
		result.OutputFile = ""
		log.Printf("[TOOL] %s: completed (no findings)", td.Name)
		return result
	}

	result.Status = "ran_successfully"
	result.OutputFile = td.OutputFile
	log.Printf("[TOOL] %s: completed -> %s", td.Name, td.OutputFile)
	return result
}

func getToolVersion(binary string) string {
	for _, flag := range []string{"--version", "version", "-v"} {
		cmd := exec.Command(binary, flag)
		out, err := cmd.Output()
		if err == nil {
			v := strings.TrimSpace(string(out))
			if len(v) > 80 {
				v = v[:80]
			}
			return v
		}
	}
	return "unknown"
}

// ToolResultsForAgent filters tool results for a specific agent.
func ToolResultsForAgent(results []ToolResult, agent string) []ToolResult {
	var filtered []ToolResult
	for _, r := range results {
		if r.Agent == agent {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ReadToolOutput reads the raw JSON output from a tool result file.
func ReadToolOutput(result ToolResult) (string, error) {
	if result.OutputFile == "" {
		return "", nil
	}
	data, err := os.ReadFile(result.OutputFile)
	if err != nil {
		return "", fmt.Errorf("read %s output: %w", result.Name, err)
	}
	// Truncate very large outputs for LLM consumption
	s := string(data)
	if len(s) > 100000 {
		s = s[:100000] + "\n... [TRUNCATED — full output in " + result.OutputFile + "]"
	}
	return s, nil
}
