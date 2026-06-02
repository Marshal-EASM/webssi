package export

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewScanner(t *testing.T) {
	scanner, err := NewScanner()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	if scanner.concurrency == 0 {
		t.Error("expected non-zero concurrency")
	}
	if !scanner.verify {
		t.Error("expected verify to be true by default")
	}
	if !scanner.skipTLSVerify {
		t.Error("expected skipTLSVerify to be true by default")
	}
}

func TestNewScannerWithOptions(t *testing.T) {
	scanner, err := NewScanner(
		WithConcurrency(4),
		WithVerify(false),
		WithIncludeDetectors("aws,github"),
		WithExcludeDetectors("slack"),
		WithFilterEntropy(3.0),
		WithFilterUnverified(true),
		WithSkipTLSVerify(false),
	)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	if scanner.concurrency != 4 {
		t.Errorf("expected concurrency 4, got %d", scanner.concurrency)
	}
	if scanner.verify {
		t.Error("expected verify to be false")
	}
	if scanner.includeDetectors != "aws,github" {
		t.Errorf("expected includeDetectors 'aws,github', got %s", scanner.includeDetectors)
	}
	if scanner.excludeDetectors != "slack" {
		t.Errorf("expected excludeDetectors 'slack', got %s", scanner.excludeDetectors)
	}
	if scanner.filterEntropy != 3.0 {
		t.Errorf("expected filterEntropy 3.0, got %f", scanner.filterEntropy)
	}
	if !scanner.filterUnverified {
		t.Error("expected filterUnverified to be true")
	}
	if scanner.skipTLSVerify {
		t.Error("expected skipTLSVerify to be false")
	}
}

func TestScanPathEmpty(t *testing.T) {
	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	_, err = scanner.ScanPath(ctx)
	if err == nil {
		t.Error("expected error for empty paths")
	}
}

func TestScanPathNonExistent(t *testing.T) {
	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	_, err = scanner.ScanPath(ctx, "/non/existent/path")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestScanURLsEmpty(t *testing.T) {
	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	_, err = scanner.ScanURLs(ctx, []string{})
	if err == nil {
		t.Error("expected error for empty URLs")
	}
}

func TestScanContentEmpty(t *testing.T) {
	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	_, err = scanner.ScanContent(ctx, []byte{})
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestScanString(t *testing.T) {
	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	// Test with a string that contains a fake AWS key pattern
	testContent := `
	Some text here
	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	More text here
	`

	output, err := scanner.ScanString(ctx, testContent)
	if err != nil {
		t.Fatalf("failed to scan string: %v", err)
	}

	if output == nil {
		t.Error("expected non-nil output")
	}
}

func TestScanURLs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`))
	}))
	defer server.Close()

	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	result, err := scanner.ScanURLs(ctx, []string{server.URL})
	if err != nil {
		t.Fatalf("failed to scan URLs: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestScanURLsWithMockHTTPServer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`
DATABASE_URL=postgres://user:password123@localhost:5432/mydb
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`))
	}))
	defer server.Close()

	scanner, err := NewScanner(WithVerify(false))
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	result, err := scanner.ScanURLs(ctx, []string{server.URL})
	if err != nil {
		t.Fatalf("failed to scan mock HTTP server: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if requests.Load() == 0 {
		t.Fatal("expected mock HTTP server to be requested")
	}
}
