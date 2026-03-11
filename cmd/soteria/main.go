package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/CodeSoteria/soteria/agents"
	"github.com/CodeSoteria/soteria/internal/config"
	"github.com/CodeSoteria/soteria/internal/db"
	"github.com/CodeSoteria/soteria/internal/jira"
	"github.com/CodeSoteria/soteria/internal/scanner"
	"github.com/CodeSoteria/soteria/internal/scheduler"
)

var cfgFile string

func main() {
	root := &cobra.Command{
		Use:   "soteria",
		Short: "CodeSoteria — Automated Security Audit Platform",
		Long:  "Orchestrates security scanners, tracks vulnerabilities in a database, and integrates with Jira for ticket management.",
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "soteria.yaml", "config file path")

	root.AddCommand(
		scanCmd(),
		startCmd(),
		reposCmd(),
		findingsCmd(),
		jiraCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadApp() (*config.Config, *db.DB, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	database, err := db.New(cfg.Database)
	if err != nil {
		return nil, nil, fmt.Errorf("init database: %w", err)
	}

	return cfg, database, nil
}

// ---- scan command ----

func scanCmd() *cobra.Command {
	var scanType string
	var report bool
	var toolsOnly bool
	var llmModel string

	cmd := &cobra.Command{
		Use:   "scan <repo-name-or-path>",
		Short: "Run a security scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			target := args[0]
			s := scanner.New(database, cfg)

			// Resolve or register repository
			repo, _ := database.GetRepository(target)
			if repo == nil {
				repo = &db.Repository{
					Name:          filepath.Base(target),
					URL:           target,
					Branch:        "main",
					ScanType:      scanType,
					ReportEnabled: report,
				}
				if err := database.CreateRepository(repo); err != nil {
					return fmt.Errorf("register repo: %w", err)
				}
			}

			ctx := context.Background()

			// Quick scan: re-check existing findings
			if scanType == scanner.ScanTypeQuick {
				result, err := s.RunQuick(ctx, repo)
				if err != nil {
					return err
				}
				printScanResult(result)
				return nil
			}

			// Full scan: pipeline (tools → files → agents enrich)
			targetPath, err := s.PrepareRepo(repo)
			if err != nil {
				return fmt.Errorf("prepare repo: %w", err)
			}

			scan, err := s.CreateScanRecord(repo, scanner.ScanTypeFull)
			if err != nil {
				return err
			}

			// Set up output directory
			outputDir := filepath.Join("codesoteria-output", repo.Name)

			// Choose LLM client
			var llm agents.LLMClient
			if toolsOnly {
				llm = &agents.NoOpLLMClient{}
			} else {
				llm = agents.NewClaudeCodeClient(llmModel)
			}

			// Build and run pipeline
			pipeline := agents.NewPipeline(outputDir, llm, cfg.Scanner.ParallelAgents)

			// Select agents
			agentNames := agents.AgentNames()
			if toolsOnly {
				agentNames = agents.ToolAgentNames()
			}

			pipelineResult, err := pipeline.Run(ctx, targetPath, agentNames)
			if err != nil {
				s.FailScan(scan.ID, err.Error())
				return fmt.Errorf("pipeline: %w", err)
			}

			// Persist to database
			newCount, openCount, mitigatedCount, err := s.PersistFindings(repo.ID, scan.ID, pipelineResult.Consolidated)
			if err != nil {
				s.FailScan(scan.ID, err.Error())
				return fmt.Errorf("persist findings: %w", err)
			}

			s.CompleteScan(scan.ID, newCount, openCount, mitigatedCount)

			result := &scanner.ScanResult{
				RepoName:       repo.Name,
				CommitHash:     scan.CommitHash,
				ScanType:       scanner.ScanTypeFull,
				Findings:       pipelineResult.Consolidated,
				NewCount:       newCount,
				OpenCount:      openCount,
				MitigatedCount: mitigatedCount,
			}

			if report {
				if err := s.GenerateReport(repo, result); err != nil {
					log.Printf("Report generation error: %v", err)
				}
			}

			printScanResult(result)

			// Jira sync
			jiraClient := jira.New(cfg.Jira, database)
			if jiraClient != nil {
				if err := jiraClient.SyncFindings(repo.ID); err != nil {
					log.Printf("Jira sync warning: %v", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&scanType, "type", "t", "full", "Scan type: quick or full")
	cmd.Flags().BoolVarP(&report, "report", "r", false, "Generate report files")
	cmd.Flags().BoolVar(&toolsOnly, "tools-only", false, "Run only external tools without LLM enrichment")
	cmd.Flags().StringVar(&llmModel, "model", "", "Claude model to use (passed to claude CLI --model flag)")
	return cmd
}

// ---- start command ----

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the scheduler daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			s := scanner.New(database, cfg)
			jiraClient := jira.New(cfg.Jira, database)
			sched := scheduler.New(s, database, jiraClient, cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				log.Println("Shutting down scheduler...")
				cancel()
			}()

			fmt.Println("CodeSoteria scheduler starting...")
			return sched.Start(ctx)
		},
	}
}

// ---- repos command ----

func reposCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repos",
		Short: "Manage repositories",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured repositories",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			repos, err := database.ListRepositories()
			if err != nil {
				return err
			}

			if len(repos) == 0 {
				fmt.Println("No repositories configured.")
				return nil
			}

			fmt.Printf("%-20s %-40s %-10s %-10s %-20s\n", "NAME", "URL", "BRANCH", "SCAN TYPE", "SCHEDULE")
			fmt.Println(strings.Repeat("-", 105))
			for _, r := range repos {
				schedule := r.ScanSchedule
				if schedule == "" {
					schedule = "(manual)"
				}
				fmt.Printf("%-20s %-40s %-10s %-10s %-20s\n", r.Name, r.URL, r.Branch, r.ScanType, schedule)
			}
			return nil
		},
	}

	var repoURL, branch, schedule, scanType string
	var reportEnabled bool
	addCmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			repo := &db.Repository{
				Name:          args[0],
				URL:           repoURL,
				Branch:        branch,
				ScanSchedule:  schedule,
				ScanType:      scanType,
				ReportEnabled: reportEnabled,
			}
			if err := database.CreateRepository(repo); err != nil {
				return err
			}
			fmt.Printf("Repository '%s' added (id=%d)\n", repo.Name, repo.ID)
			return nil
		},
	}
	addCmd.Flags().StringVar(&repoURL, "url", "", "Repository URL")
	addCmd.Flags().StringVar(&branch, "branch", "main", "Branch to scan")
	addCmd.Flags().StringVar(&schedule, "schedule", "", "Cron schedule (e.g., '0 2 * * 1')")
	addCmd.Flags().StringVar(&scanType, "scan-type", "full", "Scan type: quick or full")
	addCmd.Flags().BoolVar(&reportEnabled, "report", true, "Enable report generation")
	addCmd.MarkFlagRequired("url")

	removeCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			repo, err := database.GetRepository(args[0])
			if err != nil {
				return err
			}
			if repo == nil {
				return fmt.Errorf("repository '%s' not found", args[0])
			}
			if err := database.DeleteRepository(repo.ID); err != nil {
				return err
			}
			fmt.Printf("Repository '%s' removed\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(listCmd, addCmd, removeCmd)
	return cmd
}

// ---- findings command ----

func findingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Query and manage findings",
	}

	var repoName, severity, status string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			var repoID int64
			if repoName != "" {
				repo, err := database.GetRepository(repoName)
				if err != nil {
					return err
				}
				if repo == nil {
					return fmt.Errorf("repository '%s' not found", repoName)
				}
				repoID = repo.ID
			}

			findings, err := database.ListFindings(repoID, status, severity)
			if err != nil {
				return err
			}

			if len(findings) == 0 {
				fmt.Println("No findings match the criteria.")
				return nil
			}

			fmt.Printf("%-5s %-10s %-10s %-5s %-8s %-30s %s\n", "ID", "SEVERITY", "STATUS", "PRI", "AGENT", "TITLE", "FILE")
			fmt.Println(strings.Repeat("-", 120))
			for _, f := range findings {
				title := f.Title
				if len(title) > 30 {
					title = title[:27] + "..."
				}
				fileLoc := f.FilePath
				if f.LineStart > 0 {
					fileLoc = fmt.Sprintf("%s:%d", f.FilePath, f.LineStart)
				}
				fmt.Printf("%-5d %-10s %-10s %-5s %-8s %-30s %s\n",
					f.ID, f.Severity, f.Status, f.Priority, f.Agent, title, fileLoc)
			}
			fmt.Printf("\nTotal: %d findings\n", len(findings))
			return nil
		},
	}
	listCmd.Flags().StringVar(&repoName, "repo", "", "Filter by repository name")
	listCmd.Flags().StringVar(&severity, "severity", "", "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
	listCmd.Flags().StringVar(&status, "status", "", "Filter by status (open, mitigated, false_positive, accepted)")

	var exportFormat string
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export findings to JSON or CSV",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			var repoID int64
			if repoName != "" {
				repo, err := database.GetRepository(repoName)
				if err != nil {
					return err
				}
				if repo != nil {
					repoID = repo.ID
				}
			}

			findings, err := database.ListFindings(repoID, "", "")
			if err != nil {
				return err
			}

			switch exportFormat {
			case "csv":
				w := csv.NewWriter(os.Stdout)
				w.Write([]string{"ID", "Agent", "Severity", "Confidence", "Priority", "Title", "File", "Line", "Status", "CWE"})
				for _, f := range findings {
					w.Write([]string{
						strconv.FormatInt(f.ID, 10),
						f.Agent, f.Severity, f.Confidence, f.Priority, f.Title,
						f.FilePath, strconv.Itoa(f.LineStart), f.Status, f.CweID,
					})
				}
				w.Flush()
			default:
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(findings)
			}
			return nil
		},
	}
	exportCmd.Flags().StringVar(&repoName, "repo", "", "Filter by repository name")
	exportCmd.Flags().StringVar(&exportFormat, "format", "json", "Output format: json or csv")

	updateCmd := &cobra.Command{
		Use:   "update <finding-id> <status>",
		Short: "Update finding status (open, false_positive, accepted)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid finding ID: %s", args[0])
			}

			validStatuses := map[string]bool{"open": true, "false_positive": true, "accepted": true, "mitigated": true}
			if !validStatuses[args[1]] {
				return fmt.Errorf("invalid status '%s'; use: open, false_positive, accepted, mitigated", args[1])
			}

			if err := database.UpdateFindingStatus(id, args[1]); err != nil {
				return err
			}
			fmt.Printf("Finding %d status updated to '%s'\n", id, args[1])
			return nil
		},
	}

	cmd.AddCommand(listCmd, exportCmd, updateCmd)
	return cmd
}

// ---- jira command ----

func jiraCmd() *cobra.Command {
	var repoName string
	cmd := &cobra.Command{
		Use:   "jira sync",
		Short: "Sync findings to Jira",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, err := loadApp()
			if err != nil {
				return err
			}
			defer database.Close()

			if !cfg.Jira.Enabled {
				return fmt.Errorf("Jira integration is not enabled in config")
			}

			jiraClient := jira.New(cfg.Jira, database)
			if jiraClient == nil {
				return fmt.Errorf("failed to initialize Jira client")
			}

			repos, err := database.ListRepositories()
			if err != nil {
				return err
			}

			for _, repo := range repos {
				if repoName != "" && repo.Name != repoName {
					continue
				}
				fmt.Printf("Syncing findings for %s...\n", repo.Name)
				if err := jiraClient.SyncFindings(repo.ID); err != nil {
					log.Printf("Error syncing %s: %v", repo.Name, err)
				}
			}

			fmt.Println("Jira sync complete.")
			return nil
		},
	}
	cmd.Flags().StringVar(&repoName, "repo", "", "Filter by repository name")
	return cmd
}

func printScanResult(result *scanner.ScanResult) {
	fmt.Printf("\n=== Scan Complete: %s ===\n", result.RepoName)
	fmt.Printf("Commit: %s\n", result.CommitHash)
	fmt.Printf("Type: %s\n", result.ScanType)
	fmt.Printf("Total findings: %d\n", len(result.Findings))
	fmt.Printf("New: %d | Open: %d | Mitigated: %d\n\n", result.NewCount, result.OpenCount, result.MitigatedCount)

	if len(result.Findings) > 0 {
		limit := 10
		if len(result.Findings) < limit {
			limit = len(result.Findings)
		}
		fmt.Printf("Top %d findings:\n", limit)
		for i := 0; i < limit; i++ {
			f := result.Findings[i]
			fmt.Printf("  [%s/%s] %s — %s:%d\n", f.Severity, f.Priority, f.Title, f.FilePath, f.LineStart)
		}
		if len(result.Findings) > limit {
			fmt.Printf("  ... and %d more\n", len(result.Findings)-limit)
		}
	}

	if result.Summary != "" {
		fmt.Printf("\n%s\n", result.Summary)
	}
}
