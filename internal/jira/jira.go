package jira

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/CodeSoteria/soteria/internal/config"
	"github.com/CodeSoteria/soteria/internal/db"
)

// Client manages Jira API interactions.
type Client struct {
	cfg    config.JiraConfig
	db     *db.DB
	client *http.Client
}

// New creates a new Jira client. Returns nil if Jira is not enabled.
func New(cfg config.JiraConfig, database *db.DB) *Client {
	if !cfg.Enabled {
		return nil
	}
	return &Client{
		cfg:    cfg,
		db:     database,
		client: &http.Client{},
	}
}

// SyncFindings creates Jira tickets for findings that meet the severity threshold.
func (c *Client) SyncFindings(repoID int64) error {
	if c == nil {
		return nil
	}

	findings, err := c.db.GetFindingsWithoutJira(repoID, c.cfg.AutoCreateThreshold)
	if err != nil {
		return fmt.Errorf("get findings: %w", err)
	}

	log.Printf("[JIRA] %d findings need tickets (threshold: %s)", len(findings), c.cfg.AutoCreateThreshold)

	for _, f := range findings {
		key, url, err := c.createIssue(f)
		if err != nil {
			log.Printf("[JIRA] Failed to create ticket for finding %d: %v", f.ID, err)
			continue
		}

		// Update finding with Jira key
		if err := c.db.UpdateFindingJiraKey(f.ID, key); err != nil {
			log.Printf("[JIRA] Failed to update finding %d with Jira key: %v", f.ID, err)
		}

		// Create Jira ticket record
		ticket := &db.JiraTicket{
			FindingID: f.ID,
			JiraKey:   key,
			JiraURL:   url,
			Status:    "open",
		}
		if err := c.db.CreateJiraTicket(ticket); err != nil {
			log.Printf("[JIRA] Failed to save ticket record: %v", err)
		}

		log.Printf("[JIRA] Created %s for: %s", key, f.Title)
	}

	return nil
}

// TransitionMitigated updates Jira tickets for mitigated findings.
func (c *Client) TransitionMitigated(repoID int64) error {
	if c == nil {
		return nil
	}

	findings, err := c.db.ListFindings(repoID, "mitigated", "")
	if err != nil {
		return err
	}

	for _, f := range findings {
		if f.JiraKey == "" {
			continue
		}
		// Add a comment that the finding has been mitigated
		if err := c.addComment(f.JiraKey, "This vulnerability has been detected as mitigated by CodeSoteria automated scan."); err != nil {
			log.Printf("[JIRA] Failed to comment on %s: %v", f.JiraKey, err)
		}
	}

	return nil
}

func (c *Client) createIssue(f *db.Finding) (string, string, error) {
	priority := c.mapPriority(f.Priority)

	description := fmt.Sprintf(
		"h2. Security Finding: %s\n\n"+
			"*Agent:* %s\n"+
			"*Severity:* %s\n"+
			"*Confidence:* %s\n"+
			"*Priority:* %s\n"+
			"*Category:* %s\n",
		f.Title, f.Agent, f.Severity, f.Confidence, f.Priority, f.Category,
	)

	if f.CweID != "" {
		description += fmt.Sprintf("*CWE:* %s\n", f.CweID)
	}
	if f.FilePath != "" {
		description += fmt.Sprintf("*File:* %s:%d-%d\n", f.FilePath, f.LineStart, f.LineEnd)
	}
	if f.Description != "" {
		description += fmt.Sprintf("\nh3. Description\n%s\n", f.Description)
	}
	if f.Snippet != "" {
		description += fmt.Sprintf("\nh3. Code Snippet\n{code}%s{code}\n", f.Snippet)
	}
	if f.Remediation != "" {
		description += fmt.Sprintf("\nh3. Remediation\n%s\n", f.Remediation)
	}

	body := map[string]any{
		"fields": map[string]any{
			"project": map[string]string{
				"key": c.cfg.Project,
			},
			"summary":   fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			"description": description,
			"issuetype": map[string]string{
				"name": c.cfg.IssueType,
			},
			"priority": map[string]string{
				"name": priority,
			},
			"labels": []string{"security", "codesoteria", strings.ToLower(f.Agent)},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest("POST", c.cfg.URL+"/rest/api/2/issue", bytes.NewReader(jsonBody))
	if err != nil {
		return "", "", err
	}
	req.SetBasicAuth(c.cfg.Email, c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("jira request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("jira API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", err
	}

	issueURL := fmt.Sprintf("%s/browse/%s", c.cfg.URL, result.Key)
	return result.Key, issueURL, nil
}

func (c *Client) addComment(issueKey, comment string) error {
	body := map[string]string{"body": comment}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/rest/api/2/issue/%s/comment", c.cfg.URL, issueKey),
		bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.Email, c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("jira comment error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (c *Client) mapPriority(p string) string {
	if mapped, ok := c.cfg.PriorityMapping[p]; ok {
		return mapped
	}
	// Defaults
	switch p {
	case "P0":
		return "Highest"
	case "P1":
		return "High"
	case "P2":
		return "Medium"
	default:
		return "Low"
	}
}
