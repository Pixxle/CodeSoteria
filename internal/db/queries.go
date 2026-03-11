package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ---- Repositories ----

func (d *DB) CreateRepository(r *Repository) error {
	res, err := d.Exec(`
		INSERT INTO repositories (name, url, clone_path, branch, scan_schedule, scan_type, report_enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.URL, r.ClonePath, r.Branch, r.ScanSchedule, r.ScanType, r.ReportEnabled,
	)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (d *DB) GetRepository(name string) (*Repository, error) {
	r := &Repository{}
	err := d.QueryRow(`SELECT id, name, url, clone_path, branch, scan_schedule, scan_type, report_enabled, created_at, updated_at
		FROM repositories WHERE name = ?`, name).Scan(
		&r.ID, &r.Name, &r.URL, &r.ClonePath, &r.Branch, &r.ScanSchedule, &r.ScanType, &r.ReportEnabled, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (d *DB) GetRepositoryByID(id int64) (*Repository, error) {
	r := &Repository{}
	err := d.QueryRow(`SELECT id, name, url, clone_path, branch, scan_schedule, scan_type, report_enabled, created_at, updated_at
		FROM repositories WHERE id = ?`, id).Scan(
		&r.ID, &r.Name, &r.URL, &r.ClonePath, &r.Branch, &r.ScanSchedule, &r.ScanType, &r.ReportEnabled, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (d *DB) ListRepositories() ([]*Repository, error) {
	rows, err := d.Query(`SELECT id, name, url, clone_path, branch, scan_schedule, scan_type, report_enabled, created_at, updated_at
		FROM repositories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*Repository
	for rows.Next() {
		r := &Repository{}
		if err := rows.Scan(&r.ID, &r.Name, &r.URL, &r.ClonePath, &r.Branch, &r.ScanSchedule, &r.ScanType, &r.ReportEnabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		repos = append(repos, r)
	}
	return repos, rows.Err()
}

func (d *DB) UpdateRepository(r *Repository) error {
	r.UpdatedAt = time.Now()
	_, err := d.Exec(`UPDATE repositories SET url=?, clone_path=?, branch=?, scan_schedule=?, scan_type=?, report_enabled=?, updated_at=?
		WHERE id=?`, r.URL, r.ClonePath, r.Branch, r.ScanSchedule, r.ScanType, r.ReportEnabled, r.UpdatedAt, r.ID)
	return err
}

func (d *DB) DeleteRepository(id int64) error {
	_, err := d.Exec("DELETE FROM repositories WHERE id = ?", id)
	return err
}

// ---- Scans ----

func (d *DB) CreateScan(s *Scan) error {
	res, err := d.Exec(`INSERT INTO scans (repo_id, scan_type, status, commit_hash) VALUES (?, ?, ?, ?)`,
		s.RepoID, s.ScanType, s.Status, s.CommitHash)
	if err != nil {
		return err
	}
	s.ID, _ = res.LastInsertId()
	return nil
}

func (d *DB) UpdateScanStatus(id int64, status string, summaryJSON string, errMsg string) error {
	now := time.Now()
	var startedAt, completedAt *time.Time
	switch status {
	case "running":
		startedAt = &now
	case "completed", "failed":
		completedAt = &now
	}

	query := "UPDATE scans SET status = ?"
	args := []any{status}

	if startedAt != nil {
		query += ", started_at = ?"
		args = append(args, startedAt)
	}
	if completedAt != nil {
		query += ", completed_at = ?"
		args = append(args, completedAt)
	}
	if summaryJSON != "" {
		query += ", summary_json = ?"
		args = append(args, summaryJSON)
	}
	if errMsg != "" {
		query += ", error_message = ?"
		args = append(args, errMsg)
	}

	query += " WHERE id = ?"
	args = append(args, id)

	_, err := d.Exec(query, args...)
	return err
}

func (d *DB) GetScan(id int64) (*Scan, error) {
	s := &Scan{}
	err := d.QueryRow(`SELECT id, repo_id, scan_type, status, commit_hash, started_at, completed_at, summary_json, error_message, created_at
		FROM scans WHERE id = ?`, id).Scan(
		&s.ID, &s.RepoID, &s.ScanType, &s.Status, &s.CommitHash, &s.StartedAt, &s.CompletedAt, &s.SummaryJSON, &s.ErrorMessage, &s.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (d *DB) ListScans(repoID int64, limit int) ([]*Scan, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.Query(`SELECT id, repo_id, scan_type, status, commit_hash, started_at, completed_at, summary_json, error_message, created_at
		FROM scans WHERE repo_id = ? ORDER BY created_at DESC LIMIT ?`, repoID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		s := &Scan{}
		if err := rows.Scan(&s.ID, &s.RepoID, &s.ScanType, &s.Status, &s.CommitHash, &s.StartedAt, &s.CompletedAt, &s.SummaryJSON, &s.ErrorMessage, &s.CreatedAt); err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// ---- Findings ----

func (d *DB) UpsertFinding(f *Finding) error {
	// Check if a finding with this fingerprint already exists for this repo
	var existingID int64
	var firstSeenScanID int64
	err := d.QueryRow(`SELECT id, first_seen_scan_id FROM findings WHERE repo_id = ? AND fingerprint = ? AND status != 'mitigated'`,
		f.RepoID, f.Fingerprint).Scan(&existingID, &firstSeenScanID)

	if err == sql.ErrNoRows {
		// New finding
		res, err := d.Exec(`INSERT INTO findings (repo_id, scan_id, agent, finding_id, title, description, severity, confidence, priority,
			category, cwe_id, owasp_category, file_path, line_start, line_end, snippet, evidence, source, source_tool,
			remediation, remediation_effort, code_suggestion, false_positive_risk, status, fingerprint, first_seen_scan_id, last_seen_scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.RepoID, f.ScanID, f.Agent, f.FindingID, f.Title, f.Description, f.Severity, f.Confidence, f.Priority,
			f.Category, f.CweID, f.OwaspCategory, f.FilePath, f.LineStart, f.LineEnd, f.Snippet, f.Evidence, f.Source, f.SourceTool,
			f.Remediation, f.RemediationEffort, f.CodeSuggestion, f.FalsePositiveRisk, "open", f.Fingerprint, f.ScanID, f.ScanID)
		if err != nil {
			return err
		}
		f.ID, _ = res.LastInsertId()
		f.FirstSeenScanID = f.ScanID
		f.LastSeenScanID = f.ScanID
		return nil
	}
	if err != nil {
		return err
	}

	// Existing finding — update last_seen and refresh details
	f.ID = existingID
	f.FirstSeenScanID = firstSeenScanID
	f.LastSeenScanID = f.ScanID
	_, err = d.Exec(`UPDATE findings SET scan_id=?, last_seen_scan_id=?, severity=?, confidence=?, priority=?,
		snippet=?, evidence=?, line_start=?, line_end=?, updated_at=? WHERE id=?`,
		f.ScanID, f.ScanID, f.Severity, f.Confidence, f.Priority,
		f.Snippet, f.Evidence, f.LineStart, f.LineEnd, time.Now(), existingID)
	return err
}

func (d *DB) ListFindings(repoID int64, status string, severity string) ([]*Finding, error) {
	query := "SELECT id, repo_id, scan_id, agent, finding_id, title, description, severity, confidence, priority, category, cwe_id, file_path, line_start, line_end, snippet, status, fingerprint, first_seen_scan_id, last_seen_scan_id, jira_key, created_at, updated_at FROM findings WHERE 1=1"
	var args []any

	if repoID > 0 {
		query += " AND repo_id = ?"
		args = append(args, repoID)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}
	query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END, created_at DESC"

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		f := &Finding{}
		if err := rows.Scan(&f.ID, &f.RepoID, &f.ScanID, &f.Agent, &f.FindingID, &f.Title, &f.Description,
			&f.Severity, &f.Confidence, &f.Priority, &f.Category, &f.CweID, &f.FilePath, &f.LineStart, &f.LineEnd,
			&f.Snippet, &f.Status, &f.Fingerprint, &f.FirstSeenScanID, &f.LastSeenScanID, &f.JiraKey,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (d *DB) GetOpenFindingsForRepo(repoID int64) ([]*Finding, error) {
	return d.ListFindings(repoID, "open", "")
}

func (d *DB) MarkFindingMitigated(id int64, scanID int64) error {
	_, err := d.Exec("UPDATE findings SET status = 'mitigated', last_seen_scan_id = ?, updated_at = ? WHERE id = ?",
		scanID, time.Now(), id)
	return err
}

func (d *DB) UpdateFindingStatus(id int64, status string) error {
	_, err := d.Exec("UPDATE findings SET status = ?, updated_at = ? WHERE id = ?", status, time.Now(), id)
	return err
}

func (d *DB) UpdateFindingJiraKey(id int64, jiraKey string) error {
	_, err := d.Exec("UPDATE findings SET jira_key = ?, updated_at = ? WHERE id = ?", jiraKey, time.Now(), id)
	return err
}

func (d *DB) GetFindingsWithoutJira(repoID int64, minSeverity string) ([]*Finding, error) {
	severities := severitiesAtOrAbove(minSeverity)
	if len(severities) == 0 {
		return nil, nil
	}

	placeholders := ""
	args := []any{repoID}
	for i, s := range severities {
		if i > 0 {
			placeholders += ", "
		}
		placeholders += "?"
		args = append(args, s)
	}

	query := fmt.Sprintf(`SELECT id, repo_id, scan_id, agent, finding_id, title, description, severity, confidence, priority,
		category, cwe_id, file_path, line_start, line_end, snippet, status, fingerprint, first_seen_scan_id, last_seen_scan_id, jira_key, created_at, updated_at
		FROM findings WHERE repo_id = ? AND status = 'open' AND (jira_key IS NULL OR jira_key = '') AND severity IN (%s)
		ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END`, placeholders)

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		f := &Finding{}
		if err := rows.Scan(&f.ID, &f.RepoID, &f.ScanID, &f.Agent, &f.FindingID, &f.Title, &f.Description,
			&f.Severity, &f.Confidence, &f.Priority, &f.Category, &f.CweID, &f.FilePath, &f.LineStart, &f.LineEnd,
			&f.Snippet, &f.Status, &f.Fingerprint, &f.FirstSeenScanID, &f.LastSeenScanID, &f.JiraKey,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func severitiesAtOrAbove(level string) []string {
	switch level {
	case "CRITICAL":
		return []string{"CRITICAL"}
	case "HIGH":
		return []string{"CRITICAL", "HIGH"}
	case "MEDIUM":
		return []string{"CRITICAL", "HIGH", "MEDIUM"}
	case "LOW":
		return []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	default:
		return []string{"CRITICAL", "HIGH"}
	}
}

// ---- Jira Tickets ----

func (d *DB) CreateJiraTicket(t *JiraTicket) error {
	res, err := d.Exec(`INSERT INTO jira_tickets (finding_id, jira_key, jira_url, status) VALUES (?, ?, ?, ?)`,
		t.FindingID, t.JiraKey, t.JiraURL, t.Status)
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

func (d *DB) GetJiraTicketByFinding(findingID int64) (*JiraTicket, error) {
	t := &JiraTicket{}
	err := d.QueryRow(`SELECT id, finding_id, jira_key, jira_url, status, created_at, updated_at
		FROM jira_tickets WHERE finding_id = ?`, findingID).Scan(
		&t.ID, &t.FindingID, &t.JiraKey, &t.JiraURL, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}
