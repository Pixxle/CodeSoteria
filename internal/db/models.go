package db

import "time"

type Repository struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	ClonePath     string    `json:"clone_path"`
	Branch        string    `json:"branch"`
	ScanSchedule  string    `json:"scan_schedule"`
	ScanType      string    `json:"scan_type"`
	ReportEnabled bool      `json:"report_enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Scan struct {
	ID           int64      `json:"id"`
	RepoID       int64      `json:"repo_id"`
	ScanType     string     `json:"scan_type"`
	Status       string     `json:"status"` // pending, running, completed, failed
	CommitHash   string     `json:"commit_hash"`
	StartedAt    *time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	SummaryJSON  string     `json:"summary_json"`
	ErrorMessage string     `json:"error_message"`
	CreatedAt    time.Time  `json:"created_at"`
}

type Finding struct {
	ID                int64     `json:"id"`
	RepoID            int64     `json:"repo_id"`
	ScanID            int64     `json:"scan_id"`
	Agent             string    `json:"agent"`
	FindingID         string    `json:"finding_id"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	Severity          string    `json:"severity"`
	Confidence        string    `json:"confidence"`
	Priority          string    `json:"priority"`
	Category          string    `json:"category"`
	CweID             string    `json:"cwe_id"`
	OwaspCategory     string    `json:"owasp_category"`
	FilePath          string    `json:"file_path"`
	LineStart         int       `json:"line_start"`
	LineEnd           int       `json:"line_end"`
	Snippet           string    `json:"snippet"`
	Evidence          string    `json:"evidence"`
	Source            string    `json:"source"`
	SourceTool        string    `json:"source_tool"`
	Remediation       string    `json:"remediation"`
	RemediationEffort string    `json:"remediation_effort"`
	CodeSuggestion    string    `json:"code_suggestion"`
	FalsePositiveRisk string    `json:"false_positive_risk"`
	Status            string    `json:"status"` // open, mitigated, false_positive, accepted
	Fingerprint       string    `json:"fingerprint"`
	FirstSeenScanID   int64     `json:"first_seen_scan_id"`
	LastSeenScanID    int64     `json:"last_seen_scan_id"`
	JiraKey           string    `json:"jira_key"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type JiraTicket struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	JiraKey   string    `json:"jira_key"`
	JiraURL   string    `json:"jira_url"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
