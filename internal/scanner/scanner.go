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
	"time"

	"github.com/CodeSoteria/soteria/internal/config"
	"github.com/CodeSoteria/soteria/internal/db"
)

// AgentRunner is the interface scanner agents implement.
type AgentRunner interface {
	Name() string
	Run(ctx context.Context, targetPath string) ([]*RawFinding, error)
}

// Scanner orchestrates security scans.
type Scanner struct {
	DB     *db.DB
	Config *config.Config
	Agents []AgentRunner
}

// New creates a new Scanner.
func New(database *db.DB, cfg *config.Config, agents []AgentRunner) *Scanner {
	return &Scanner{
		DB:     database,
		Config: cfg,
		Agents: agents,
	}
}

// RunFull executes a full scan against the given repository.
func (s *Scanner) RunFull(ctx context.Context, repo *db.Repository, generateReport bool) (*ScanResult, error) {
	targetPath, err := s.prepareRepo(repo)
	if err != nil {
		return nil, fmt.Errorf("prepare repo: %w", err)
	}

	commitHash := getCommitHash(targetPath)

	// Create scan record
	scan := &db.Scan{
		RepoID:     repo.ID,
		ScanType:   ScanTypeFull,
		Status:     "running",
		CommitHash: commitHash,
	}
	if err := s.DB.CreateScan(scan); err != nil {
		return nil, fmt.Errorf("create scan: %w", err)
	}
	now := time.Now()
	scan.StartedAt = &now
	s.DB.UpdateScanStatus(scan.ID, "running", "", "")

	// Run all agents in parallel
	var allFindings []*RawFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, agent := range s.Agents {
		wg.Add(1)
		go func(a AgentRunner) {
			defer wg.Done()
			log.Printf("[%s] Starting scan...", a.Name())
			findings, err := a.Run(ctx, targetPath)
			if err != nil {
				log.Printf("[%s] Error: %v", a.Name(), err)
				return
			}
			log.Printf("[%s] Found %d findings", a.Name(), len(findings))
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(agent)
	}
	wg.Wait()

	// Deduplicate by fingerprint
	allFindings = dedup(allFindings)

	// Persist findings and diff against existing
	newCount, openCount, mitigatedCount, err := s.persistFindings(repo.ID, scan.ID, allFindings)
	if err != nil {
		s.DB.UpdateScanStatus(scan.ID, "failed", "", err.Error())
		return nil, fmt.Errorf("persist findings: %w", err)
	}

	result := &ScanResult{
		RepoName:       repo.Name,
		CommitHash:     commitHash,
		ScanType:       ScanTypeFull,
		Findings:       allFindings,
		NewCount:       newCount,
		OpenCount:      openCount,
		MitigatedCount: mitigatedCount,
	}

	summaryJSON, _ := json.Marshal(map[string]int{
		"total":    len(allFindings),
		"new":      newCount,
		"open":     openCount,
		"mitigated": mitigatedCount,
	})
	s.DB.UpdateScanStatus(scan.ID, "completed", string(summaryJSON), "")

	if generateReport {
		if err := s.generateReport(repo, result); err != nil {
			log.Printf("Report generation error: %v", err)
		}
	}

	return result, nil
}

// RunQuick re-checks existing open findings to see if they've been mitigated.
func (s *Scanner) RunQuick(ctx context.Context, repo *db.Repository) (*ScanResult, error) {
	targetPath, err := s.prepareRepo(repo)
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

	// Get all open findings for this repo
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
			// File no longer exists — finding is mitigated
			s.DB.MarkFindingMitigated(f.ID, scan.ID)
			mitigated++
			continue
		}

		// Check if the vulnerable code snippet is still present
		if f.Snippet != "" && !strings.Contains(string(content), strings.TrimSpace(f.Snippet)) {
			s.DB.MarkFindingMitigated(f.ID, scan.ID)
			mitigated++
			continue
		}

		// For dependency findings, re-run a quick dep check
		if f.Agent == "DEPS" {
			// Just check if the file content changed (version bumped)
			s.DB.UpdateScanStatus(scan.ID, "running", "", "")
			stillOpen++
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

// persistFindings stores findings and diffs against existing ones.
func (s *Scanner) persistFindings(repoID, scanID int64, findings []*RawFinding) (newCount, openCount, mitigatedCount int, err error) {
	// Get existing open findings
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

	// Mark findings not seen in this scan as mitigated
	for fp, existing := range existingFPs {
		if !seenFPs[fp] {
			if err := s.DB.MarkFindingMitigated(existing.ID, scanID); err != nil {
				log.Printf("Failed to mark finding %d as mitigated: %v", existing.ID, err)
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

// prepareRepo clones or pulls the repository.
func (s *Scanner) prepareRepo(repo *db.Repository) (string, error) {
	cloneDir := s.Config.Scanner.CloneDir
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		return "", err
	}

	targetPath := filepath.Join(cloneDir, repo.Name)

	if repo.URL == "" || strings.HasPrefix(repo.URL, "/") || strings.HasPrefix(repo.URL, ".") {
		// Local path — use directly
		if repo.URL != "" {
			targetPath = repo.URL
		}
		return targetPath, nil
	}

	if _, err := os.Stat(filepath.Join(targetPath, ".git")); err == nil {
		// Already cloned — pull latest
		cmd := exec.Command("git", "-C", targetPath, "pull", "origin", repo.Branch)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: git pull failed for %s: %v", repo.Name, err)
		}
	} else {
		// Clone
		cmd := exec.Command("git", "clone", "--branch", repo.Branch, "--depth", "1", repo.URL, targetPath)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	}

	// Update repo clone_path
	repo.ClonePath = targetPath
	s.DB.UpdateRepository(repo)

	return targetPath, nil
}

func getCommitHash(path string) string {
	cmd := exec.Command("git", "-C", path, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// dedup removes duplicate findings by fingerprint.
func dedup(findings []*RawFinding) []*RawFinding {
	seen := make(map[string]bool)
	var result []*RawFinding
	for _, f := range findings {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		result = append(result, f)
	}
	return result
}

// generateReport writes a markdown report to disk.
func (s *Scanner) generateReport(repo *db.Repository, result *ScanResult) error {
	outputDir := filepath.Join(".", "codesoteria-output", repo.Name)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// JSON report
	jsonPath := filepath.Join(outputDir, "security-audit.json")
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return err
	}

	// Markdown report
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
	b.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Total Findings | %d |\n", len(result.Findings)))
	b.WriteString(fmt.Sprintf("| New | %d |\n", result.NewCount))
	b.WriteString(fmt.Sprintf("| Still Open | %d |\n", result.OpenCount))
	b.WriteString(fmt.Sprintf("| Mitigated | %d |\n\n", result.MitigatedCount))

	// Group by severity
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
