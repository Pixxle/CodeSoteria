package scanner

// Severity levels.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Confidence levels.
const (
	ConfidenceHigh   = "HIGH"
	ConfidenceMedium = "MEDIUM"
	ConfidenceLow    = "LOW"
)

// Finding statuses.
const (
	StatusOpen          = "open"
	StatusMitigated     = "mitigated"
	StatusFalsePositive = "false_positive"
	StatusAccepted      = "accepted"
)

// Scan types.
const (
	ScanTypeQuick = "quick"
	ScanTypeFull  = "full"
)

// RawFinding is the output from an individual agent before DB persistence.
type RawFinding struct {
	Agent             string `json:"agent"`
	FindingID         string `json:"finding_id"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	Confidence        string `json:"confidence"`
	Priority          string `json:"priority"`
	Category          string `json:"category"`
	CweID             string `json:"cwe_id,omitempty"`
	OwaspCategory     string `json:"owasp_category,omitempty"`
	FilePath          string `json:"file_path"`
	LineStart         int    `json:"line_start"`
	LineEnd           int    `json:"line_end"`
	Snippet           string `json:"snippet,omitempty"`
	Evidence          string `json:"evidence,omitempty"`
	Source            string `json:"source"`
	SourceTool        string `json:"source_tool,omitempty"`
	Remediation       string `json:"remediation,omitempty"`
	RemediationEffort string `json:"remediation_effort,omitempty"`
	CodeSuggestion    string `json:"code_suggestion,omitempty"`
	FalsePositiveRisk string `json:"false_positive_risk,omitempty"`
	Fingerprint       string `json:"fingerprint"`
}

// ToolStatus represents the availability of an external security tool.
type ToolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
}

// ScanResult is the full output of a scan run.
type ScanResult struct {
	RepoName    string        `json:"repo_name"`
	CommitHash  string        `json:"commit_hash"`
	ScanType    string        `json:"scan_type"`
	Findings    []*RawFinding `json:"findings"`
	NewCount    int           `json:"new_count"`
	OpenCount   int           `json:"open_count"`
	MitigatedCount int       `json:"mitigated_count"`
	Summary     string        `json:"summary"`
}

// Priority computes priority from severity x confidence.
func Priority(severity, confidence string) string {
	switch severity {
	case SeverityCritical:
		if confidence == ConfidenceLow {
			return "P1"
		}
		return "P0"
	case SeverityHigh:
		if confidence == ConfidenceLow {
			return "P2"
		}
		return "P1"
	case SeverityMedium:
		if confidence == ConfidenceLow {
			return "P3"
		}
		return "P2"
	default:
		return "P3"
	}
}
