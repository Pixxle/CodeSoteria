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
	"time"

	"github.com/CodeSoteria/soteria/internal/config"
	"github.com/CodeSoteria/soteria/internal/db"
)

// Scanner orchestrates security scans with database persistence.
type Scanner struct {
	DB     *db.DB
	Config *config.Config
}

// New creates a new Scanner.
func New(database *db.DB, cfg *config.Config) *Scanner {
	return &Scanner{
		DB:     database,
		Config: cfg,
	}
}

// PersistFindings stores pipeline findings in the database, diffing against existing.
func (s *Scanner) PersistFindings(repoID, scanID int64, findings []*RawFinding) (newCount, openCount, mitigatedCount int, err error) {
	existing, err := s.DB.GetOpenFindingsForRepo(repoID)
	if err != nil {
		return 0, 0, 0, err
	}

	existingFPs := make(map[string]*db.Finding)
	for _, f := range existing {
		existingFPs[f.Fingerprint] = f
	}

	seenFPs := make(map[string]bool)

	for _, raw := range findings {
		seenFPs[raw.Fingerprint] = true

		f := &db.Finding{
			RepoID:            repoID,
			ScanID:            scanID,
			Agent:             raw.Agent,
			FindingID:         raw.FindingID,
			Title:             raw.Title,
			Description:       raw.Description,
			Severity:          raw.Severity,
			Confidence:        raw.Confidence,
			Priority:          raw.Priority,
			Category:          raw.Category,
			CweID:             raw.CweID,
			OwaspCategory:     raw.OwaspCategory,
			FilePath:          raw.FilePath,
			LineStart:         raw.LineStart,
			LineEnd:           raw.LineEnd,
			Snippet:           raw.Snippet,
			Evidence:          raw.Evidence,
			Source:            raw.Source,
			SourceTool:        raw.SourceTool,
			Remediation:       raw.Remediation,
			RemediationEffort: raw.RemediationEffort,
			CodeSuggestion:    raw.CodeSuggestion,
			FalsePositiveRisk: raw.FalsePositiveRisk,
			Fingerprint:       raw.Fingerprint,
		}

		if err := s.DB.UpsertFinding(f); err != nil {
			return 0, 0, 0, fmt.Errorf("upsert finding: %w", err)
		}

		if _, existed := existingFPs[raw.Fingerprint]; !existed {
			newCount++
		}
	}

	for fp, ef := range existingFPs {
		if !seenFPs[fp] {
			if err := s.DB.MarkFindingMitigated(ef.ID, scanID); err != nil {
				log.Printf("Failed to mark finding %d mitigated: %v", ef.ID, err)
			}
			mitigatedCount++
		}
	}

	openCount = len(findings) - newCount + (len(existing) - mitigatedCount)
	if openCount < 0 {
		openCount = 0
	}

	return newCount, openCount + newCount, mitigatedCount, nil
}

// CreateScanRecord creates a new scan record in the database.
func (s *Scanner) CreateScanRecord(repo *db.Repository, scanType string) (*db.Scan, error) {
	targetPath, _ := s.RepoPath(repo)
	commitHash := getCommitHash(targetPath)

	scan := &db.Scan{
		RepoID:     repo.ID,
		ScanType:   scanType,
		Status:     "running",
		CommitHash: commitHash,
	}
	if err := s.DB.CreateScan(scan); err != nil {
		return nil, err
	}
	s.DB.UpdateScanStatus(scan.ID, "running", "", "")
	return scan, nil
}

// CompleteScan marks a scan as completed with summary stats.
func (s *Scanner) CompleteScan(scanID int64, newCount, openCount, mitigatedCount int) {
	summaryJSON, _ := json.Marshal(map[string]int{
		"new":       newCount,
		"open":      openCount,
		"mitigated": mitigatedCount,
	})
	s.DB.UpdateScanStatus(scanID, "completed", string(summaryJSON), "")
}

// FailScan marks a scan as failed.
func (s *Scanner) FailScan(scanID int64, errMsg string) {
	s.DB.UpdateScanStatus(scanID, "failed", "", errMsg)
}

// RunQuick re-checks existing open findings to see if they've been mitigated.
func (s *Scanner) RunQuick(ctx context.Context, repo *db.Repository) (*ScanResult, error) {
	targetPath, err := s.PrepareRepo(repo)
	if err != nil {
		return nil, fmt.Errorf("prepare repo: %w", err)
	}

	commitHash := getCommitHash(targetPath)

	scan := &db.Scan{
		RepoID:     repo.ID,
		ScanType:   ScanTypeQuick,
		Status:     "running",
		CommitHash: commitHash,
	}
	if err := s.DB.CreateScan(scan); err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}
	s.DB.UpdateScanStatus(scan.ID, "running", "", "")

	openFindings, err := s.DB.GetOpenFindingsForRepo(repo.ID)
	if err != nil {
		s.DB.UpdateScanStatus(scan.ID, "failed", "", err.Error())
		return nil, fmt.Errorf("get open findings: %w", err)
	}

	mitigated := 0
	stillOpen := 0

	for _, f := range openFindings {
		if f.FilePath == "" {
			stillOpen++
			continue
		}

		fullPath := filepath.Join(targetPath, f.FilePath)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			s.DB.MarkFindingMitigated(f.ID, scan.ID)
			mitigated++
			continue
		}

		if f.Snippet != "" && !strings.Contains(string(content), strings.TrimSpace(f.Snippet)) {
			s.DB.MarkFindingMitigated(f.ID, scan.ID)
			mitigated++
			continue
		}

		stillOpen++
	}

	result := &ScanResult{
		RepoName:       repo.Name,
		CommitHash:     commitHash,
		ScanType:       ScanTypeQuick,
		OpenCount:      stillOpen,
		MitigatedCount: mitigated,
		Summary:        fmt.Sprintf("Quick scan: %d still open, %d mitigated", stillOpen, mitigated),
	}

	summaryJSON, _ := json.Marshal(map[string]int{
		"checked":   len(openFindings),
		"open":      stillOpen,
		"mitigated": mitigated,
	})
	s.DB.UpdateScanStatus(scan.ID, "completed", string(summaryJSON), "")

	return result, nil
}

// PrepareRepo clones or pulls the repository and returns the local path.
func (s *Scanner) PrepareRepo(repo *db.Repository) (string, error) {
	cloneDir := s.Config.Scanner.CloneDir
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		return "", err
	}

	targetPath := filepath.Join(cloneDir, repo.Name)

	if repo.URL == "" || strings.HasPrefix(repo.URL, "/") || strings.HasPrefix(repo.URL, ".") {
		if repo.URL != "" {
			targetPath = repo.URL
		}
		return targetPath, nil
	}

	if _, err := os.Stat(filepath.Join(targetPath, ".git")); err == nil {
		cmd := exec.Command("git", "-C", targetPath, "pull", "origin", repo.Branch)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: git pull failed for %s: %v", repo.Name, err)
		}
	} else {
		cmd := exec.Command("git", "clone", "--branch", repo.Branch, "--depth", "1", repo.URL, targetPath)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	}

	repo.ClonePath = targetPath
	s.DB.UpdateRepository(repo)

	return targetPath, nil
}

// RepoPath returns the local path for a repo without pulling.
func (s *Scanner) RepoPath(repo *db.Repository) (string, error) {
	if repo.URL == "" || strings.HasPrefix(repo.URL, "/") || strings.HasPrefix(repo.URL, ".") {
		if repo.URL != "" {
			return repo.URL, nil
		}
		return filepath.Join(s.Config.Scanner.CloneDir, repo.Name), nil
	}
	return filepath.Join(s.Config.Scanner.CloneDir, repo.Name), nil
}

func getCommitHash(path string) string {
	cmd := exec.Command("git", "-C", path, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// GenerateReport writes markdown and JSON reports to disk.
func (s *Scanner) GenerateReport(repo *db.Repository, result *ScanResult) error {
	outputDir := filepath.Join(".", "codesoteria-output", repo.Name)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	jsonPath := filepath.Join(outputDir, "security-audit.json")
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return err
	}

	mdPath := filepath.Join(outputDir, "security-audit.md")
	md := buildMarkdownReport(repo, result)
	if err := os.WriteFile(mdPath, []byte(md), 0644); err != nil {
		return err
	}

	log.Printf("Reports written to %s", outputDir)
	return nil
}

func buildMarkdownReport(repo *db.Repository, result *ScanResult) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Security Audit Report: %s\n\n", repo.Name))
	b.WriteString(fmt.Sprintf("**Commit:** %s\n", result.CommitHash))
	b.WriteString(fmt.Sprintf("**Scan Type:** %s\n", result.ScanType))
	b.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Findings | %d |\n", len(result.Findings)))
	b.WriteString(fmt.Sprintf("| New | %d |\n", result.NewCount))
	b.WriteString(fmt.Sprintf("| Still Open | %d |\n", result.OpenCount))
	b.WriteString(fmt.Sprintf("| Mitigated | %d |\n\n", result.MitigatedCount))

	bySev := map[string][]*RawFinding{}
	for _, f := range result.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}

	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		findings := bySev[sev]
		if len(findings) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s (%d)\n\n", sev, len(findings)))
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("### %s\n\n", f.Title))
			b.WriteString(fmt.Sprintf("- **Agent:** %s\n", f.Agent))
			b.WriteString(fmt.Sprintf("- **File:** %s:%d\n", f.FilePath, f.LineStart))
			b.WriteString(fmt.Sprintf("- **Priority:** %s\n", f.Priority))
			if f.CweID != "" {
				b.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CweID))
			}
			b.WriteString(fmt.Sprintf("\n%s\n\n", f.Description))
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
			}
			b.WriteString("---\n\n")
		}
	}

	return b.String()
}
