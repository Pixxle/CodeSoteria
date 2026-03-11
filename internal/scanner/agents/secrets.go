package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

type SecretsAgent struct{}

func NewSecretsAgent() *SecretsAgent { return &SecretsAgent{} }
func (a *SecretsAgent) Name() string { return "SECRETS" }

func (a *SecretsAgent) Run(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	var findings []*scanner.RawFinding

	if toolAvailable("gitleaks") {
		f, err := a.runGitleaks(ctx, targetPath)
		if err != nil {
			log.Printf("[SECRETS] gitleaks error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("trufflehog") {
		f, err := a.runTruffleHog(ctx, targetPath)
		if err != nil {
			log.Printf("[SECRETS] trufflehog error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

func (a *SecretsAgent) runGitleaks(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "gitleaks", "detect", "--source", targetPath, "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner")
	if err != nil {
		return nil, err
	}

	var results []struct {
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		EndLine     int    `json:"EndLine"`
		Match       string `json:"Match"`
		Secret      string `json:"Secret"`
		RuleID      string `json:"RuleID"`
		Entropy     float64 `json:"Entropy"`
		Fingerprint string `json:"Fingerprint"`
	}

	if err := json.Unmarshal([]byte(out), &results); err != nil {
		// No findings = empty output or non-JSON
		if len(out) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("parse gitleaks output: %w", err)
	}

	var findings []*scanner.RawFinding
	for i, r := range results {
		// Mask the secret in evidence
		masked := r.Match
		if len(r.Secret) > 4 {
			masked = r.Secret[:4] + "****"
		}

		f := &scanner.RawFinding{
			Agent:             "SECRETS",
			FindingID:         fmt.Sprintf("SECRETS-GL%03d", i+1),
			Title:             fmt.Sprintf("Hardcoded %s", r.Description),
			Description:       fmt.Sprintf("Found %s in source code", r.Description),
			Severity:          scanner.SeverityHigh,
			Confidence:        scanner.ConfidenceHigh,
			Priority:          scanner.Priority(scanner.SeverityHigh, scanner.ConfidenceHigh),
			Category:          "secrets",
			CweID:             "CWE-798",
			FilePath:          r.File,
			LineStart:         r.StartLine,
			LineEnd:           r.EndLine,
			Snippet:           masked,
			Evidence:          fmt.Sprintf("Rule: %s, Entropy: %.2f", r.RuleID, r.Entropy),
			Source:            "tool",
			SourceTool:        "gitleaks",
			Remediation:       "Remove the secret from source code, rotate the credential, and use environment variables or a secrets manager.",
			RemediationEffort: "LOW",
			FalsePositiveRisk: "LOW",
			Fingerprint:       fingerprint("SECRETS", r.File, r.RuleID, r.StartLine),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func (a *SecretsAgent) runTruffleHog(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "trufflehog", "filesystem", "--json", "--no-update", targetPath)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}

	// TruffleHog outputs one JSON object per line
	var findings []*scanner.RawFinding
	idx := 0
	for _, line := range splitLines(out) {
		if len(line) == 0 {
			continue
		}
		var r struct {
			DetectorName string `json:"DetectorName"`
			Raw          string `json:"Raw"`
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		idx++

		masked := ""
		if len(r.Raw) > 4 {
			masked = r.Raw[:4] + "****"
		}

		f := &scanner.RawFinding{
			Agent:             "SECRETS",
			FindingID:         fmt.Sprintf("SECRETS-TH%03d", idx),
			Title:             fmt.Sprintf("Hardcoded %s", r.DetectorName),
			Description:       fmt.Sprintf("TruffleHog detected a %s secret", r.DetectorName),
			Severity:          scanner.SeverityHigh,
			Confidence:        scanner.ConfidenceHigh,
			Priority:          scanner.Priority(scanner.SeverityHigh, scanner.ConfidenceHigh),
			Category:          "secrets",
			CweID:             "CWE-798",
			FilePath:          r.SourceMetadata.Data.Filesystem.File,
			LineStart:         r.SourceMetadata.Data.Filesystem.Line,
			LineEnd:           r.SourceMetadata.Data.Filesystem.Line,
			Snippet:           masked,
			Source:            "tool",
			SourceTool:        "trufflehog",
			Remediation:       "Remove the secret, rotate the credential, use a secrets manager.",
			RemediationEffort: "LOW",
			FalsePositiveRisk: "LOW",
			Fingerprint:       fingerprint("SECRETS", r.SourceMetadata.Data.Filesystem.File, r.DetectorName, r.SourceMetadata.Data.Filesystem.Line),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
