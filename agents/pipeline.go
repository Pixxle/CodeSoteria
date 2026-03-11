package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

// Pipeline orchestrates the full scan pipeline:
// 1. Run external tools (store raw output to files)
// 2. Feed tool results + source code to LLM agents for enrichment
// 3. Consolidate and cross-correlate findings
type Pipeline struct {
	ToolRunner *scanner.ToolRunner
	LLM        LLMClient
	OutputDir  string
	MaxAgents  int // max parallel agent invocations
}

// NewPipeline creates a new scan pipeline.
func NewPipeline(outputDir string, llm LLMClient, maxAgents int) *Pipeline {
	if maxAgents <= 0 {
		maxAgents = 4
	}
	return &Pipeline{
		ToolRunner: scanner.NewToolRunner(outputDir),
		LLM:        llm,
		OutputDir:  outputDir,
		MaxAgents:  maxAgents,
	}
}

// PipelineResult is the output of a full pipeline run.
type PipelineResult struct {
	ToolResults  []scanner.ToolResult       `json:"tool_results"`
	AgentResults map[string][]*scanner.RawFinding `json:"agent_results"`
	Consolidated []*scanner.RawFinding      `json:"consolidated"`
	Summary      string                     `json:"summary"`
}

// Run executes the full pipeline against a target path.
func (p *Pipeline) Run(ctx context.Context, targetPath string, agentNames []string) (*PipelineResult, error) {
	result := &PipelineResult{
		AgentResults: make(map[string][]*scanner.RawFinding),
	}

	// Phase 1: Run all external tools
	log.Println("[PIPELINE] Phase 1: Running external tools...")
	toolResults, err := p.ToolRunner.RunAllTools(ctx, targetPath)
	if err != nil {
		return nil, fmt.Errorf("tool execution: %w", err)
	}
	result.ToolResults = toolResults

	toolSummary := summarizeToolResults(toolResults)
	log.Printf("[PIPELINE] Tools complete: %s", toolSummary)

	// Collect source files for LLM review
	sourceFiles := collectSourceFiles(targetPath)

	// Phase 2: Run LLM agents in parallel
	log.Println("[PIPELINE] Phase 2: Running LLM agents...")
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.MaxAgents)

	for _, agentName := range agentNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			findings, err := p.runAgent(ctx, name, toolResults, sourceFiles)
			if err != nil {
				log.Printf("[PIPELINE] Agent %s error: %v", name, err)
				return
			}

			mu.Lock()
			result.AgentResults[name] = findings
			mu.Unlock()

			// Save agent findings to file
			if err := SaveAgentResult(p.OutputDir, name, findings); err != nil {
				log.Printf("[PIPELINE] Failed to save %s results: %v", name, err)
			}

			log.Printf("[PIPELINE] Agent %s: %d findings", name, len(findings))
		}(agentName)
	}
	wg.Wait()

	// Phase 3: Consolidation
	log.Println("[PIPELINE] Phase 3: Consolidating findings...")
	consolidated, err := p.consolidate(ctx, result.AgentResults)
	if err != nil {
		log.Printf("[PIPELINE] Consolidation error: %v, using raw agent results", err)
		// Fallback: just combine all findings
		for _, findings := range result.AgentResults {
			consolidated = append(consolidated, findings...)
		}
	}
	result.Consolidated = consolidated

	// Save consolidated findings
	consolidatedPath := filepath.Join(p.OutputDir, "findings", "consolidated.json")
	os.MkdirAll(filepath.Dir(consolidatedPath), 0755)
	data, _ := json.MarshalIndent(consolidated, "", "  ")
	os.WriteFile(consolidatedPath, data, 0644)

	log.Printf("[PIPELINE] Complete: %d consolidated findings", len(consolidated))
	return result, nil
}

// runAgent renders the prompt, calls the LLM, and parses the response.
func (p *Pipeline) runAgent(ctx context.Context, agentName string, toolResults []scanner.ToolResult, sourceFiles []SourceFile) ([]*scanner.RawFinding, error) {
	input, err := BuildAgentInput(agentName, toolResults, sourceFiles)
	if err != nil {
		return nil, fmt.Errorf("build input: %w", err)
	}

	prompt, err := RenderPrompt(agentName, input)
	if err != nil {
		return nil, fmt.Errorf("render prompt: %w", err)
	}

	// Save rendered prompt for audit
	SavePromptToFile(p.OutputDir, agentName, prompt)

	systemPrompt := fmt.Sprintf("You are the %s security analysis agent for CodeSoteria. "+
		"Analyze the provided tool outputs and source code, then return findings as a JSON array. "+
		"Be thorough but filter obvious false positives. Return ONLY valid JSON.", agentName)

	response, err := p.LLM.Complete(systemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM call: %w", err)
	}

	// Save raw LLM response for debugging
	responsePath := filepath.Join(p.OutputDir, "responses", agentName+"-response.txt")
	os.MkdirAll(filepath.Dir(responsePath), 0755)
	os.WriteFile(responsePath, []byte(response), 0644)

	findings, err := ParseAgentResponse(agentName, response)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return findings, nil
}

// consolidate runs the cross-correlation agent on all findings.
func (p *Pipeline) consolidate(ctx context.Context, agentResults map[string][]*scanner.RawFinding) ([]*scanner.RawFinding, error) {
	var inputs []AgentResult
	for name, findings := range agentResults {
		data, _ := json.MarshalIndent(findings, "", "  ")
		inputs = append(inputs, AgentResult{
			Agent:        name,
			FindingCount: len(findings),
			FindingsJSON: string(data),
			Findings:     findings,
		})
	}

	prompt, err := RenderConsolidatePrompt(ConsolidateInput{AgentResults: inputs})
	if err != nil {
		return nil, err
	}

	SavePromptToFile(p.OutputDir, "consolidate", prompt)

	systemPrompt := "You are the consolidation agent for CodeSoteria. " +
		"Deduplicate, cross-correlate, and identify compound findings across all agent results. " +
		"Return ONLY valid JSON."

	response, err := p.LLM.Complete(systemPrompt, prompt)
	if err != nil {
		return nil, err
	}

	// Save response
	responsePath := filepath.Join(p.OutputDir, "responses", "consolidate-response.txt")
	os.WriteFile(responsePath, []byte(response), 0644)

	// Parse — consolidation returns an object with a "findings" key
	extracted := extractJSON(response)
	var consolidated struct {
		Findings []*scanner.RawFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(extracted), &consolidated); err != nil {
		// Try as plain array
		findings, err2 := ParseAgentResponse("CONSOLIDATED", extracted)
		if err2 != nil {
			return nil, fmt.Errorf("parse consolidation: %w", err)
		}
		return findings, nil
	}

	return consolidated.Findings, nil
}

// collectSourceFiles gathers relevant source files from the target.
func collectSourceFiles(targetPath string) []SourceFile {
	var files []SourceFile
	exts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".cs": true, ".rs": true,
		".yml": true, ".yaml": true, ".json": true, ".toml": true,
		".tf": true, ".hcl": true,
		".env": true, ".ini": true, ".cfg": true, ".conf": true,
	}

	// Also include specific filenames
	names := map[string]bool{
		"Dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
		"Jenkinsfile": true, ".gitlab-ci.yml": true,
		"Makefile": true, "Gemfile": true, "Cargo.toml": true,
		"package.json": true, "package-lock.json": true,
		"go.mod": true, "go.sum": true,
		"requirements.txt": true, "Pipfile": true, "pyproject.toml": true,
		".gitignore": true,
	}

	maxFiles := 100
	maxFileSize := int64(50000) // 50KB per file

	filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			// Skip hidden dirs and common non-source dirs
			if info != nil && info.IsDir() {
				base := filepath.Base(path)
				if base == "node_modules" || base == "vendor" || base == ".git" || base == "__pycache__" || base == ".venv" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if len(files) >= maxFiles {
			return filepath.SkipAll
		}

		if info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}

		ext := filepath.Ext(path)
		base := filepath.Base(path)
		if !exts[ext] && !names[base] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(targetPath, path)
		files = append(files, SourceFile{
			Path:    rel,
			Content: string(content),
		})

		return nil
	})

	return files
}

func summarizeToolResults(results []scanner.ToolResult) string {
	ran, failed, unavailable := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "ran_successfully":
			ran++
		case "failed":
			failed++
		case "unavailable":
			unavailable++
		}
	}
	return fmt.Sprintf("%d ran, %d failed, %d unavailable", ran, failed, unavailable)
}
