package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

type ConfigAgent struct{}

func NewConfigAgent() *ConfigAgent { return &ConfigAgent{} }
func (a *ConfigAgent) Name() string { return "CONFIG" }

func (a *ConfigAgent) Run(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	var findings []*scanner.RawFinding

	if toolAvailable("checkov") {
		f, err := a.runCheckov(ctx, targetPath)
		if err != nil {
			log.Printf("[CONFIG] checkov error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("hadolint") {
		f, err := a.runHadolint(ctx, targetPath)
		if err != nil {
			log.Printf("[CONFIG] hadolint error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

func (a *ConfigAgent) runCheckov(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "checkov", "-d", targetPath, "-o", "json", "--quiet", "--compact")
	if err != nil {
		return nil, err
	}

	var result struct {
		Results struct {
			FailedChecks []struct {
				CheckID     string `json:"check_id"`
				CheckResult struct {
					Result string `json:"result"`
				} `json:"check_result"`
				CheckType  string `json:"check_type"`
				FilePath   string `json:"file_path"`
				FileLineRange []int `json:"file_line_range"`
				Guideline  string `json:"guideline"`
				CheckClass string `json:"check_class"`
				Name       string `json:"name"`
			} `json:"failed_checks"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		// Checkov may return an array of results for multiple frameworks
		var results []json.RawMessage
		if err2 := json.Unmarshal([]byte(out), &results); err2 != nil {
			return nil, fmt.Errorf("parse checkov output: %w", err)
		}
		// Try parsing each element
		var findings []*scanner.RawFinding
		for _, raw := range results {
			if err := json.Unmarshal(raw, &result); err != nil {
				continue
			}
			f := a.processCheckovResults(result.Results.FailedChecks)
			findings = append(findings, f...)
		}
		return findings, nil
	}

	return a.processCheckovResults(result.Results.FailedChecks), nil
}

func (a *ConfigAgent) processCheckovResults(checks []struct {
	CheckID     string `json:"check_id"`
	CheckResult struct {
		Result string `json:"result"`
	} `json:"check_result"`
	CheckType     string `json:"check_type"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Guideline     string `json:"guideline"`
	CheckClass    string `json:"check_class"`
	Name          string `json:"name"`
}) []*scanner.RawFinding {
	var findings []*scanner.RawFinding
	for i, c := range checks {
		lineStart, lineEnd := 0, 0
		if len(c.FileLineRange) >= 2 {
			lineStart = c.FileLineRange[0]
			lineEnd = c.FileLineRange[1]
		}

		f := &scanner.RawFinding{
			Agent:       "CONFIG",
			FindingID:   fmt.Sprintf("CONFIG-CK%03d", i+1),
			Title:       fmt.Sprintf("%s: %s", c.CheckID, c.Name),
			Description: c.Name,
			Severity:    scanner.SeverityMedium,
			Confidence:  scanner.ConfidenceHigh,
			Priority:    scanner.Priority(scanner.SeverityMedium, scanner.ConfidenceHigh),
			Category:    "config",
			FilePath:    c.FilePath,
			LineStart:   lineStart,
			LineEnd:     lineEnd,
			Source:      "tool",
			SourceTool:  "checkov",
			Remediation: c.Guideline,
			Fingerprint: fingerprint("CONFIG", c.FilePath, c.CheckID, lineStart),
		}
		findings = append(findings, f)
	}
	return findings
}

func (a *ConfigAgent) runHadolint(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	// Find Dockerfiles
	dockerfiles, err := runTool(ctx, "find", targetPath, "-name", "Dockerfile*", "-type", "f")
	if err != nil || len(dockerfiles) == 0 {
		return nil, nil
	}

	var findings []*scanner.RawFinding
	idx := 0
	for _, df := range splitLines(dockerfiles) {
		if len(df) == 0 {
			continue
		}
		out, err := runTool(ctx, "hadolint", "-f", "json", df)
		if err != nil {
			continue
		}

		var results []struct {
			Line    int    `json:"line"`
			Code    string `json:"code"`
			Message string `json:"message"`
			Level   string `json:"level"`
			File    string `json:"file"`
		}
		if err := json.Unmarshal([]byte(out), &results); err != nil {
			continue
		}

		for _, r := range results {
			idx++
			sev := mapHadolintLevel(r.Level)
			f := &scanner.RawFinding{
				Agent:       "CONFIG",
				FindingID:   fmt.Sprintf("CONFIG-HL%03d", idx),
				Title:       fmt.Sprintf("%s: %s", r.Code, r.Message),
				Description: r.Message,
				Severity:    sev,
				Confidence:  scanner.ConfidenceHigh,
				Priority:    scanner.Priority(sev, scanner.ConfidenceHigh),
				Category:    "config",
				FilePath:    r.File,
				LineStart:   r.Line,
				LineEnd:     r.Line,
				Source:      "tool",
				SourceTool:  "hadolint",
				Fingerprint: fingerprint("CONFIG", r.File, r.Code, r.Line),
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func mapHadolintLevel(level string) string {
	switch level {
	case "error":
		return scanner.SeverityHigh
	case "warning":
		return scanner.SeverityMedium
	case "info", "style":
		return scanner.SeverityLow
	default:
		return scanner.SeverityMedium
	}
}
