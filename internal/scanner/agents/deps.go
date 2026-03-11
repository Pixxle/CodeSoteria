package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/CodeSoteria/soteria/internal/scanner"
)

type DepsAgent struct{}

func NewDepsAgent() *DepsAgent { return &DepsAgent{} }
func (a *DepsAgent) Name() string { return "DEPS" }

func (a *DepsAgent) Run(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	var findings []*scanner.RawFinding

	if toolAvailable("osv-scanner") {
		f, err := a.runOSVScanner(ctx, targetPath)
		if err != nil {
			log.Printf("[DEPS] osv-scanner error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("grype") {
		f, err := a.runGrype(ctx, targetPath)
		if err != nil {
			log.Printf("[DEPS] grype error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	if toolAvailable("trivy") {
		f, err := a.runTrivy(ctx, targetPath)
		if err != nil {
			log.Printf("[DEPS] trivy error: %v", err)
		} else {
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

func (a *DepsAgent) runOSVScanner(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "osv-scanner", "--format", "json", "-r", targetPath)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Severity []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
					Aliases []string `json:"aliases"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse osv-scanner output: %w", err)
	}

	var findings []*scanner.RawFinding
	idx := 0
	for _, r := range result.Results {
		for _, pkg := range r.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				idx++
				sev := scanner.SeverityMedium
				if len(vuln.Severity) > 0 {
					sev = mapCVSSSeverity(vuln.Severity[0].Score)
				}

				cve := ""
				for _, alias := range vuln.Aliases {
					if len(alias) > 4 && alias[:4] == "CVE-" {
						cve = alias
						break
					}
				}

				f := &scanner.RawFinding{
					Agent:       "DEPS",
					FindingID:   fmt.Sprintf("DEPS-O%03d", idx),
					Title:       fmt.Sprintf("%s in %s@%s", vuln.ID, pkg.Package.Name, pkg.Package.Version),
					Description: vuln.Summary,
					Severity:    sev,
					Confidence:  scanner.ConfidenceHigh,
					Priority:    scanner.Priority(sev, scanner.ConfidenceHigh),
					Category:    "dependency",
					CweID:       cve,
					FilePath:    r.Source.Path,
					Source:      "tool",
					SourceTool:  "osv-scanner",
					Remediation: fmt.Sprintf("Update %s to a patched version", pkg.Package.Name),
					Fingerprint: fingerprint("DEPS", r.Source.Path, vuln.ID, 0),
				}
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

func (a *DepsAgent) runGrype(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "grype", "dir:"+targetPath, "-o", "json", "--quiet")
	if err != nil {
		return nil, err
	}

	var result struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
		} `json:"matches"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}

	var findings []*scanner.RawFinding
	for i, m := range result.Matches {
		sev := mapGrypeSeverity(m.Vulnerability.Severity)
		filePath := ""
		if len(m.Artifact.Locations) > 0 {
			filePath = m.Artifact.Locations[0].Path
		}

		remediation := fmt.Sprintf("Update %s", m.Artifact.Name)
		if len(m.Vulnerability.Fix.Versions) > 0 {
			remediation = fmt.Sprintf("Update %s to %s", m.Artifact.Name, m.Vulnerability.Fix.Versions[0])
		}

		f := &scanner.RawFinding{
			Agent:       "DEPS",
			FindingID:   fmt.Sprintf("DEPS-G%03d", i+1),
			Title:       fmt.Sprintf("%s in %s@%s", m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description: m.Vulnerability.Description,
			Severity:    sev,
			Confidence:  scanner.ConfidenceHigh,
			Priority:    scanner.Priority(sev, scanner.ConfidenceHigh),
			Category:    "dependency",
			CweID:       m.Vulnerability.ID,
			FilePath:    filePath,
			Source:      "tool",
			SourceTool:  "grype",
			Remediation: remediation,
			Fingerprint: fingerprint("DEPS", filePath, m.Vulnerability.ID, 0),
		}
		findings = append(findings, f)
	}

	return findings, nil
}

func (a *DepsAgent) runTrivy(ctx context.Context, targetPath string) ([]*scanner.RawFinding, error) {
	out, err := runTool(ctx, "trivy", "fs", "--format", "json", "--quiet", targetPath)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				PkgName         string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion    string `json:"FixedVersion"`
				Severity        string `json:"Severity"`
				Title           string `json:"Title"`
				Description     string `json:"Description"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}

	var findings []*scanner.RawFinding
	idx := 0
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			idx++
			sev := mapTrivySeverity(v.Severity)
			remediation := fmt.Sprintf("Update %s", v.PkgName)
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Update %s to %s", v.PkgName, v.FixedVersion)
			}

			f := &scanner.RawFinding{
				Agent:       "DEPS",
				FindingID:   fmt.Sprintf("DEPS-T%03d", idx),
				Title:       fmt.Sprintf("%s in %s@%s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Description: v.Description,
				Severity:    sev,
				Confidence:  scanner.ConfidenceHigh,
				Priority:    scanner.Priority(sev, scanner.ConfidenceHigh),
				Category:    "dependency",
				CweID:       v.VulnerabilityID,
				FilePath:    r.Target,
				Source:      "tool",
				SourceTool:  "trivy",
				Remediation: remediation,
				Fingerprint: fingerprint("DEPS", r.Target, v.VulnerabilityID, 0),
			}
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func mapCVSSSeverity(score string) string {
	// CVSS score string — try numeric parse
	var s float64
	fmt.Sscanf(score, "%f", &s)
	switch {
	case s >= 9.0:
		return scanner.SeverityCritical
	case s >= 7.0:
		return scanner.SeverityHigh
	case s >= 4.0:
		return scanner.SeverityMedium
	default:
		return scanner.SeverityLow
	}
}

func mapGrypeSeverity(s string) string {
	switch s {
	case "Critical":
		return scanner.SeverityCritical
	case "High":
		return scanner.SeverityHigh
	case "Medium":
		return scanner.SeverityMedium
	case "Low", "Negligible":
		return scanner.SeverityLow
	default:
		return scanner.SeverityMedium
	}
}

func mapTrivySeverity(s string) string {
	switch s {
	case "CRITICAL":
		return scanner.SeverityCritical
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
