package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

type SASTAgent struct{}

func NewSASTAgent() *SASTAgent { return &SASTAgent{} }
func (a *SASTAgent) Name() string { return "SAST" }

func (a *SASTAgent) Run(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	var findings []*scanner.RawFinding

	if toolAvailable("semgrep") {
		f, err := a.runSemgrep(ctx, targetPath)
		if err != nil {
			log.Printf("[SAST] semgrep error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("bandit") {
		f, err := a.runBandit(ctx, targetPath)
		if err != nil {
			log.Printf("[SAST] bandit error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("gosec") {
		f, err := a.runGosec(ctx, targetPath)
		if err != nil {
			log.Printf("[SAST] gosec error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

func (a *SASTAgent) runSemgrep(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "semgrep", "scan", "--json", "--quiet", targetPath)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Metadata struct {
					CweID    []string `json:"cwe"`
					Category string   `json:"category"`
					Owasp    []string `json:"owasp"`
				} `json:"metadata"`
				Lines string `json:"lines"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse semgrep output: %w", err)
	}

	var findings []*scanner.RawFinding
	for i, r := range result.Results {
		sev := mapSemgrepSeverity(r.Extra.Severity)
		cwe := ""
		if len(r.Extra.Metadata.CweID) > 0 {
			cwe = r.Extra.Metadata.CweID[0]
		}
		owasp := ""
		if len(r.Extra.Metadata.Owasp) > 0 {
			owasp = r.Extra.Metadata.Owasp[0]
		}

		f := &scanner.RawFinding{
			Agent:       "SAST",
			FindingID:   fmt.Sprintf("SAST-S%03d", i+1),
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Severity:    sev,
			Confidence:  scanner.ConfidenceHigh,
			Priority:    scanner.Priority(sev, scanner.ConfidenceHigh),
			Category:    r.Extra.Metadata.Category,
			CweID:       cwe,
			OwaspCategory: owasp,
			FilePath:    r.Path,
			LineStart:   r.Start.Line,
			LineEnd:     r.End.Line,
			Snippet:     r.Extra.Lines,
			Source:      "tool",
			SourceTool:  "semgrep",
			Fingerprint: fingerprint("SAST", r.Path, r.CheckID, r.Start.Line),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func (a *SASTAgent) runBandit(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "bandit", "-r", "-f", "json", "-q", targetPath)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			TestID     string `json:"test_id"`
			TestName   string `json:"test_name"`
			Filename   string `json:"filename"`
			LineNumber int    `json:"line_number"`
			LineRange  []int  `json:"line_range"`
			Severity   string `json:"issue_severity"`
			Confidence string `json:"issue_confidence"`
			IssueText  string `json:"issue_text"`
			Code       string `json:"code"`
			CweID      struct {
				ID int `json:"id"`
			} `json:"issue_cwe"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse bandit output: %w", err)
	}

	var findings []*scanner.RawFinding
	for i, r := range result.Results {
		sev := mapBanditSeverity(r.Severity)
		conf := mapBanditConfidence(r.Confidence)
		lineEnd := r.LineNumber
		if len(r.LineRange) > 1 {
			lineEnd = r.LineRange[len(r.LineRange)-1]
		}

		f := &scanner.RawFinding{
			Agent:       "SAST",
			FindingID:   fmt.Sprintf("SAST-B%03d", i+1),
			Title:       r.TestName,
			Description: r.IssueText,
			Severity:    sev,
			Confidence:  conf,
			Priority:    scanner.Priority(sev, conf),
			CweID:       fmt.Sprintf("CWE-%d", r.CweID.ID),
			FilePath:    r.Filename,
			LineStart:   r.LineNumber,
			LineEnd:     lineEnd,
			Snippet:     r.Code,
			Source:      "tool",
			SourceTool:  "bandit",
			Fingerprint: fingerprint("SAST", r.Filename, r.TestName, r.LineNumber),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func (a *SASTAgent) runGosec(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "gosec", "-fmt=json", "-quiet", targetPath+"/...")
	if err != nil {
		return nil, err
	}

	var result struct {
		Issues []struct {
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			RuleID     string `json:"rule_id"`
			Details    string `json:"details"`
			File       string `json:"file"`
			Code       string `json:"code"`
			Line       string `json:"line"`
			Column     string `json:"column"`
			CweID      struct {
				ID string `json:"id"`
			} `json:"cwe"`
		} `json:"Issues"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse gosec output: %w", err)
	}

	var findings []*scanner.RawFinding
	for i, r := range result.Issues {
		sev := mapGosecSeverity(r.Severity)
		conf := mapGosecConfidence(r.Confidence)
		lineStart := 0
		fmt.Sscanf(r.Line, "%d", &lineStart)

		f := &scanner.RawFinding{
			Agent:       "SAST",
			FindingID:   fmt.Sprintf("SAST-G%03d", i+1),
			Title:       r.RuleID,
			Description: r.Details,
			Severity:    sev,
			Confidence:  conf,
			Priority:    scanner.Priority(sev, conf),
			CweID:       "CWE-" + r.CweID.ID,
			FilePath:    r.File,
			LineStart:   lineStart,
			LineEnd:     lineStart,
			Snippet:     r.Code,
			Source:      "tool",
			SourceTool:  "gosec",
			Fingerprint: fingerprint("SAST", r.File, r.RuleID, lineStart),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func mapSemgrepSeverity(s string) string {
	switch s {
	case "ERROR":
		return scanner.SeverityHigh
	case "WARNING":
		return scanner.SeverityMedium
	case "INFO":
		return scanner.SeverityLow
	default:
		return scanner.SeverityMedium
	}
}

func mapBanditSeverity(s string) string {
	switch s {
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	default:
		return scanner.SeverityMedium
	}
}

func mapBanditConfidence(s string) string {
	switch s {
	case "HIGH":
		return scanner.ConfidenceHigh
	case "MEDIUM":
		return scanner.ConfidenceMedium
	case "LOW":
		return scanner.ConfidenceLow
	default:
		return scanner.ConfidenceMedium
	}
}

func mapGosecSeverity(s string) string {
	switch s {
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	default:
		return scanner.SeverityMedium
	}
}

func mapGosecConfidence(s string) string {
	switch s {
	case "HIGH":
		return scanner.ConfidenceHigh
	case "MEDIUM":
		return scanner.ConfidenceMedium
	case "LOW":
		return scanner.ConfidenceLow
	default:
		return scanner.ConfidenceMedium
	}
}
