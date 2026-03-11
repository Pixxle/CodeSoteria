-- CodeSoteria initial schema

CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    clone_path TEXT,
    branch TEXT NOT NULL DEFAULT 'main',
    scan_schedule TEXT,
    scan_type TEXT NOT NULL DEFAULT 'full',
    report_enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    commit_hash TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    summary_json TEXT,
    error_message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    scan_id INTEGER NOT NULL,
    agent TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    priority TEXT NOT NULL,
    category TEXT,
    cwe_id TEXT,
    owasp_category TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    snippet TEXT,
    evidence TEXT,
    source TEXT,
    source_tool TEXT,
    remediation TEXT,
    remediation_effort TEXT,
    code_suggestion TEXT,
    false_positive_risk TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    fingerprint TEXT NOT NULL,
    first_seen_scan_id INTEGER NOT NULL,
    last_seen_scan_id INTEGER NOT NULL,
    jira_key TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (first_seen_scan_id) REFERENCES scans(id),
    FOREIGN KEY (last_seen_scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_repo_status ON findings(repo_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);

CREATE TABLE IF NOT EXISTS jira_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    jira_key TEXT NOT NULL,
    jira_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_jira_finding ON jira_tickets(finding_id);
