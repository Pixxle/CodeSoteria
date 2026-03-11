package scheduler

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/CodeSoteria/soteria/agents"
	"github.com/CodeSoteria/soteria/internal/config"
	"github.com/CodeSoteria/soteria/internal/db"
	"github.com/CodeSoteria/soteria/internal/jira"
	"github.com/CodeSoteria/soteria/internal/scanner"
)

// Scheduler manages cron-based scan scheduling for repositories.
type Scheduler struct {
	cron    *cron.Cron
	scanner *scanner.Scanner
	db      *db.DB
	jira    *jira.Client
	cfg     *config.Config
	mu      sync.Mutex
	entries map[string]cron.EntryID
}

// New creates a new Scheduler.
func New(s *scanner.Scanner, database *db.DB, jiraClient *jira.Client, cfg *config.Config) *Scheduler {
	return &Scheduler{
		cron:    cron.New(cron.WithSeconds()),
		scanner: s,
		db:      database,
		jira:    jiraClient,
		cfg:     cfg,
		entries: make(map[string]cron.EntryID),
	}
}

// Start initializes schedules from config and starts the cron scheduler.
func (s *Scheduler) Start(ctx context.Context) error {
	for _, rc := range s.cfg.Repositories {
		if rc.Schedule == "" {
			continue
		}

		repo, err := s.db.GetRepository(rc.Name)
		if err != nil {
			log.Printf("Error getting repo %s: %v", rc.Name, err)
			continue
		}
		if repo == nil {
			repo = &db.Repository{
				Name:          rc.Name,
				URL:           rc.URL,
				Branch:        rc.Branch,
				ScanSchedule:  rc.Schedule,
				ScanType:      rc.ScanType,
				ReportEnabled: rc.Report,
			}
			if err := s.db.CreateRepository(repo); err != nil {
				log.Printf("Error registering repo %s: %v", rc.Name, err)
				continue
			}
			log.Printf("Registered repository: %s", rc.Name)
		}

		if err := s.AddRepo(ctx, repo); err != nil {
			log.Printf("Error scheduling repo %s: %v", rc.Name, err)
		}
	}

	repos, err := s.db.ListRepositories()
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if repo.ScanSchedule == "" {
			continue
		}
		s.mu.Lock()
		_, exists := s.entries[repo.Name]
		s.mu.Unlock()
		if exists {
			continue
		}
		if err := s.AddRepo(ctx, repo); err != nil {
			log.Printf("Error scheduling repo %s: %v", repo.Name, err)
		}
	}

	s.cron.Start()
	log.Printf("Scheduler started with %d repositories", len(s.entries))

	<-ctx.Done()
	s.cron.Stop()
	return nil
}

// AddRepo adds a repository to the schedule.
func (s *Scheduler) AddRepo(ctx context.Context, repo *db.Repository) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if eid, exists := s.entries[repo.Name]; exists {
		s.cron.Remove(eid)
	}

	repoName := repo.Name
	scanType := repo.ScanType
	report := repo.ReportEnabled

	entryID, err := s.cron.AddFunc(repo.ScanSchedule, func() {
		s.runScan(ctx, repoName, scanType, report)
	})
	if err != nil {
		return err
	}

	s.entries[repo.Name] = entryID
	log.Printf("Scheduled %s: %s (%s scan, report=%v)", repo.Name, repo.ScanSchedule, scanType, report)
	return nil
}

// RemoveRepo removes a repository from the schedule.
func (s *Scheduler) RemoveRepo(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if eid, exists := s.entries[name]; exists {
		s.cron.Remove(eid)
		delete(s.entries, name)
	}
}

func (s *Scheduler) runScan(ctx context.Context, repoName, scanType string, generateReport bool) {
	log.Printf("Scheduled scan starting for %s (type=%s)", repoName, scanType)

	repo, err := s.db.GetRepository(repoName)
	if err != nil || repo == nil {
		log.Printf("Error loading repo %s: %v", repoName, err)
		return
	}

	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if scanType == scanner.ScanTypeQuick {
		result, err := s.scanner.RunQuick(scanCtx, repo)
		if err != nil {
			log.Printf("Scan failed for %s: %v", repoName, err)
			return
		}
		log.Printf("Quick scan completed for %s: %d open, %d mitigated",
			repoName, result.OpenCount, result.MitigatedCount)
	} else {
		// Full scan via pipeline
		targetPath, err := s.scanner.PrepareRepo(repo)
		if err != nil {
			log.Printf("Prepare repo failed for %s: %v", repoName, err)
			return
		}

		scan, err := s.scanner.CreateScanRecord(repo, scanner.ScanTypeFull)
		if err != nil {
			log.Printf("Create scan record failed for %s: %v", repoName, err)
			return
		}

		outputDir := filepath.Join("codesoteria-output", repo.Name)
		llm := agents.NewClaudeCodeClient(s.cfg.Scanner.LLMModel)
		pipeline := agents.NewPipeline(outputDir, llm, s.cfg.Scanner.ParallelAgents)

		pipelineResult, err := pipeline.Run(scanCtx, targetPath, agents.AgentNames())
		if err != nil {
			s.scanner.FailScan(scan.ID, err.Error())
			log.Printf("Pipeline failed for %s: %v", repoName, err)
			return
		}

		newCount, openCount, mitigatedCount, err := s.scanner.PersistFindings(repo.ID, scan.ID, pipelineResult.Consolidated)
		if err != nil {
			s.scanner.FailScan(scan.ID, err.Error())
			log.Printf("Persist findings failed for %s: %v", repoName, err)
			return
		}

		s.scanner.CompleteScan(scan.ID, newCount, openCount, mitigatedCount)

		if generateReport {
			result := &scanner.ScanResult{
				RepoName:       repo.Name,
				CommitHash:     scan.CommitHash,
				ScanType:       scanner.ScanTypeFull,
				Findings:       pipelineResult.Consolidated,
				NewCount:       newCount,
				OpenCount:      openCount,
				MitigatedCount: mitigatedCount,
			}
			if err := s.scanner.GenerateReport(repo, result); err != nil {
				log.Printf("Report generation error for %s: %v", repoName, err)
			}
		}

		log.Printf("Full scan completed for %s: %d findings, %d new, %d mitigated",
			repoName, len(pipelineResult.Consolidated), newCount, mitigatedCount)
	}

	// Sync to Jira if enabled
	if s.jira != nil && s.cfg.Jira.Enabled {
		if err := s.jira.SyncFindings(repo.ID); err != nil {
			log.Printf("Jira sync error for %s: %v", repoName, err)
		}
	}
}
