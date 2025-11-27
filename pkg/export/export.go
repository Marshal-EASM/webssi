// Package export provides a simple API for other projects to use TruffleHog's
// secret scanning capabilities as a library.
//
// Example usage:
//
//	scanner, err := export.NewScanner(export.WithVerify(true))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer scanner.Close()
//
//	// Scan a file or directory
//	results, err := scanner.ScanPath(ctx, "/path/to/scan")
//
//	// Scan URLs from a file
//	results, err := scanner.ScanURLFile(ctx, "/path/to/urls.txt")
//
//	// Scan specific URLs
//	results, err := scanner.ScanURLs(ctx, []string{"https://example.com/file.txt"})
package export

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache"
)

// ScanResult represents a single secret finding.
type ScanResult struct {
	// DetectorType is the type of detector that found this secret.
	DetectorType detectorspb.DetectorType
	// DetectorName is the human-readable name of the detector.
	DetectorName string
	// Description is a description of what was detected.
	Description string
	// Verified indicates if the secret was verified to be active.
	Verified bool
	// VerificationError contains any error that occurred during verification.
	VerificationError error
	// Raw contains the raw secret data.
	Raw string
	// RawV2 contains the raw secret identifier (for multi-part secrets).
	RawV2 string
	// Redacted contains the redacted version for display purposes.
	Redacted string
	// ExtraData contains additional detector-specific information.
	ExtraData map[string]string
	// SourceMetadata contains source-specific contextual information.
	SourceMetadata *source_metadatapb.MetaData
	// SourceType is the type of source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the source.
	SourceName string
}

// ScanMetrics contains metrics about a scan.
type ScanMetrics struct {
	// BytesScanned is the total number of bytes scanned.
	BytesScanned uint64
	// ChunksScanned is the total number of chunks scanned.
	ChunksScanned uint64
	// VerifiedSecretsFound is the number of verified secrets found.
	VerifiedSecretsFound uint64
	// UnverifiedSecretsFound is the number of unverified secrets found.
	UnverifiedSecretsFound uint64
}

// ScanOutput contains the results and metrics from a scan.
type ScanOutput struct {
	// Results contains all the secrets found.
	Results []ScanResult
	// Metrics contains scan statistics.
	Metrics ScanMetrics
}

// Scanner is the main interface for scanning for secrets.
type Scanner struct {
	concurrency      int
	verify           bool
	includeDetectors string
	excludeDetectors string
	filterEntropy    float64
	filterUnverified bool
}

// Option is a function that configures a Scanner.
type Option func(*Scanner)

// WithConcurrency sets the number of concurrent workers.
func WithConcurrency(n int) Option {
	return func(s *Scanner) {
		s.concurrency = n
	}
}

// WithVerify enables or disables verification of found secrets.
func WithVerify(verify bool) Option {
	return func(s *Scanner) {
		s.verify = verify
	}
}

// WithIncludeDetectors sets which detectors to include (comma-separated list).
func WithIncludeDetectors(detectors string) Option {
	return func(s *Scanner) {
		s.includeDetectors = detectors
	}
}

// WithExcludeDetectors sets which detectors to exclude (comma-separated list).
func WithExcludeDetectors(detectors string) Option {
	return func(s *Scanner) {
		s.excludeDetectors = detectors
	}
}

// WithFilterEntropy filters unverified results by Shannon entropy.
func WithFilterEntropy(entropy float64) Option {
	return func(s *Scanner) {
		s.filterEntropy = entropy
	}
}

// WithFilterUnverified enables filtering of duplicate unverified results.
func WithFilterUnverified(filter bool) Option {
	return func(s *Scanner) {
		s.filterUnverified = filter
	}
}

// NewScanner creates a new Scanner with the given options.
func NewScanner(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:      runtime.NumCPU(),
		verify:           true,
		includeDetectors: "all",
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Close releases resources used by the Scanner.
func (s *Scanner) Close() error {
	return nil
}

// resultCollector collects scan results.
type resultCollector struct {
	mu      sync.Mutex
	results []ScanResult
}

func (c *resultCollector) Dispatch(_ context.Context, result detectors.ResultWithMetadata) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results = append(c.results, ScanResult{
		DetectorType:      result.DetectorType,
		DetectorName:      result.DetectorType.String(),
		Description:       result.DetectorDescription,
		Verified:          result.Verified,
		VerificationError: result.VerificationError(),
		Raw:               string(result.Raw),
		RawV2:             string(result.RawV2),
		Redacted:          result.Redacted,
		ExtraData:         result.ExtraData,
		SourceMetadata:    result.SourceMetadata,
		SourceType:        result.SourceType,
		SourceName:        result.SourceName,
	})
	return nil
}

// createEngine creates a new engine with the scanner's configuration.
func (s *Scanner) createEngine(ctx context.Context) (*engine.Engine, *resultCollector, error) {
	collector := &resultCollector{}

	verificationCacheMetrics := verificationcache.InMemoryMetrics{}

	opts := []func(*sources.SourceManager){
		sources.WithConcurrentSources(s.concurrency),
		sources.WithConcurrentUnits(s.concurrency),
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(64),
	}

	cfg := engine.Config{
		Concurrency:              s.concurrency,
		Detectors:                defaults.DefaultDetectors(),
		Verify:                   s.verify,
		IncludeDetectors:         s.includeDetectors,
		ExcludeDetectors:         s.excludeDetectors,
		Dispatcher:               collector,
		FilterUnverified:         s.filterUnverified,
		FilterEntropy:            s.filterEntropy,
		SourceManager:            sources.NewManager(opts...),
		VerificationResultCache:  simple.NewCache[detectors.Result](),
		VerificationCacheMetrics: &verificationCacheMetrics,
	}

	eng, err := engine.NewEngine(ctx, &cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create engine: %w", err)
	}

	return eng, collector, nil
}

// ScanPath scans a file or directory for secrets.
func (s *Scanner) ScanPath(ctx context.Context, paths ...string) (*ScanOutput, error) {
	return s.ScanPathWithOptions(ctx, FilesystemOptions{Paths: paths})
}

// FilesystemOptions contains options for filesystem scanning.
type FilesystemOptions struct {
	// Paths is the list of files or directories to scan.
	Paths []string
	// IncludePathsFile is the path to a file containing regexes for files to include.
	IncludePathsFile string
	// ExcludePathsFile is the path to a file containing regexes for files to exclude.
	ExcludePathsFile string
}

// ScanPathWithOptions scans files or directories with additional options.
func (s *Scanner) ScanPathWithOptions(ctx context.Context, opts FilesystemOptions) (*ScanOutput, error) {
	if len(opts.Paths) == 0 {
		return nil, fmt.Errorf("no paths provided")
	}

	// Validate paths exist
	for _, path := range opts.Paths {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("path %q does not exist: %w", path, err)
		}
	}

	eng, collector, err := s.createEngine(ctx)
	if err != nil {
		return nil, err
	}

	eng.Start(ctx)

	cfg := sources.FilesystemConfig{
		Paths:            opts.Paths,
		IncludePathsFile: opts.IncludePathsFile,
		ExcludePathsFile: opts.ExcludePathsFile,
	}

	if _, err := eng.ScanFileSystem(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to scan filesystem: %w", err)
	}

	if err := eng.Finish(ctx); err != nil {
		return nil, fmt.Errorf("engine failed to finish: %w", err)
	}

	metrics := eng.GetMetrics()
	return &ScanOutput{
		Results: collector.results,
		Metrics: ScanMetrics{
			BytesScanned:           metrics.BytesScanned,
			ChunksScanned:          metrics.ChunksScanned,
			VerifiedSecretsFound:   metrics.VerifiedSecretsFound,
			UnverifiedSecretsFound: metrics.UnverifiedSecretsFound,
		},
	}, nil
}

// ScanURLFile scans URLs listed in a file.
func (s *Scanner) ScanURLFile(ctx context.Context, urlFilePath string) (*ScanOutput, error) {
	if _, err := os.Stat(urlFilePath); err != nil {
		return nil, fmt.Errorf("url file %q does not exist: %w", urlFilePath, err)
	}

	eng, collector, err := s.createEngine(ctx)
	if err != nil {
		return nil, err
	}

	eng.Start(ctx)

	cfg := sources.URLConfig{
		Filename:    urlFilePath,
		Concurrency: s.concurrency,
	}

	if _, err := eng.ScanURL(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to scan URLs: %w", err)
	}

	if err := eng.Finish(ctx); err != nil {
		return nil, fmt.Errorf("engine failed to finish: %w", err)
	}

	metrics := eng.GetMetrics()
	return &ScanOutput{
		Results: collector.results,
		Metrics: ScanMetrics{
			BytesScanned:           metrics.BytesScanned,
			ChunksScanned:          metrics.ChunksScanned,
			VerifiedSecretsFound:   metrics.VerifiedSecretsFound,
			UnverifiedSecretsFound: metrics.UnverifiedSecretsFound,
		},
	}, nil
}

// ScanURLs scans a list of URLs directly.
func (s *Scanner) ScanURLs(ctx context.Context, urls []string) (*ScanOutput, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs provided")
	}

	// Create a temporary file with the URLs
	tmpFile, err := os.CreateTemp("", "trufflehog-urls-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, url := range urls {
		if _, err := tmpFile.WriteString(url + "\n"); err != nil {
			tmpFile.Close()
			return nil, fmt.Errorf("failed to write URL to temp file: %w", err)
		}
	}
	tmpFile.Close()

	return s.ScanURLFile(ctx, tmpFile.Name())
}

// ScanContent scans arbitrary content for secrets.
func (s *Scanner) ScanContent(ctx context.Context, content []byte) (*ScanOutput, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("no content provided")
	}

	// Create a temporary file with the content
	tmpFile, err := os.CreateTemp("", "trufflehog-content-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write content to temp file: %w", err)
	}
	tmpFile.Close()

	return s.ScanPath(ctx, tmpFile.Name())
}

// ScanString is a convenience method to scan a string for secrets.
func (s *Scanner) ScanString(ctx context.Context, content string) (*ScanOutput, error) {
	return s.ScanContent(ctx, []byte(content))
}

// GitOptions contains options for Git repository scanning.
type GitOptions struct {
	// URI is the git repository URL (https://, file://, or ssh://).
	URI string
	// Branch is the branch to scan.
	Branch string
	// SinceCommit is the commit to start scanning from.
	SinceCommit string
	// MaxDepth is the maximum depth of commits to scan.
	MaxDepth int
	// IncludePathsFile is the path to a file containing regexes for files to include.
	IncludePathsFile string
	// ExcludePathsFile is the path to a file containing regexes for files to exclude.
	ExcludePathsFile string
	// ExcludeGlobs is a comma-separated list of globs to exclude from scan.
	ExcludeGlobs string
	// Bare indicates whether the repository is bare.
	Bare bool
}

// ScanGit scans a git repository for secrets.
func (s *Scanner) ScanGit(ctx context.Context, opts GitOptions) (*ScanOutput, error) {
	if opts.URI == "" {
		return nil, fmt.Errorf("git URI is required")
	}

	eng, collector, err := s.createEngine(ctx)
	if err != nil {
		return nil, err
	}

	eng.Start(ctx)

	cfg := sources.GitConfig{
		URI:              opts.URI,
		HeadRef:          opts.Branch,
		BaseRef:          opts.SinceCommit,
		MaxDepth:         opts.MaxDepth,
		Bare:             opts.Bare,
		IncludePathsFile: opts.IncludePathsFile,
		ExcludePathsFile: opts.ExcludePathsFile,
		ExcludeGlobs:     opts.ExcludeGlobs,
	}

	if _, err := eng.ScanGit(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to scan git repository: %w", err)
	}

	if err := eng.Finish(ctx); err != nil {
		return nil, fmt.Errorf("engine failed to finish: %w", err)
	}

	metrics := eng.GetMetrics()
	return &ScanOutput{
		Results: collector.results,
		Metrics: ScanMetrics{
			BytesScanned:           metrics.BytesScanned,
			ChunksScanned:          metrics.ChunksScanned,
			VerifiedSecretsFound:   metrics.VerifiedSecretsFound,
			UnverifiedSecretsFound: metrics.UnverifiedSecretsFound,
		},
	}, nil
}

// ScanGitRepo is a convenience method to scan a git repository with minimal options.
func (s *Scanner) ScanGitRepo(ctx context.Context, uri string) (*ScanOutput, error) {
	return s.ScanGit(ctx, GitOptions{URI: uri})
}
