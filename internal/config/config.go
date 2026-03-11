package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database   DatabaseConfig   `yaml:"database"`
	Repositories []RepoConfig  `yaml:"repositories"`
	Jira       JiraConfig       `yaml:"jira"`
	Scanner    ScannerConfig    `yaml:"scanner"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type RepoConfig struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Branch   string `yaml:"branch"`
	Schedule string `yaml:"schedule"`
	ScanType string `yaml:"scan_type"`
	Report   bool   `yaml:"report"`
}

type JiraConfig struct {
	Enabled             bool              `yaml:"enabled"`
	URL                 string            `yaml:"url"`
	Project             string            `yaml:"project"`
	IssueType           string            `yaml:"issue_type"`
	Email               string            `yaml:"email"`
	Token               string            `yaml:"token"`
	AutoCreateThreshold string            `yaml:"auto_create_threshold"`
	PriorityMapping     map[string]string `yaml:"priority_mapping"`
}

type ScannerConfig struct {
	GitHistoryScan bool   `yaml:"git_history_scan"`
	ParallelAgents int    `yaml:"parallel_agents"`
	CloneDir       string `yaml:"clone_dir"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Expand environment variables in the config
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, err
	}

	// Defaults
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "sqlite3"
	}
	if cfg.Database.DSN == "" {
		cfg.Database.DSN = "soteria.db"
	}
	if cfg.Scanner.ParallelAgents == 0 {
		cfg.Scanner.ParallelAgents = 4
	}
	if cfg.Scanner.CloneDir == "" {
		cfg.Scanner.CloneDir = "/tmp/soteria-repos"
	}

	return &cfg, nil
}
