// Package export example - demonstrates how to use TruffleHog as a library
//
// This example shows various ways to scan for secrets using the export package.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/export"
)

func main() {
	// Create a new scanner with default options
	scanner, err := export.NewScanner(
		export.WithVerify(true),           // Enable verification
		export.WithConcurrency(4),         // Use 4 workers
		export.WithFilterUnverified(true), // Filter duplicate unverified results
	)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()

	// Example 1: Scan a directory
	fmt.Println("=== Scanning Directory ===")
	if len(os.Args) > 1 {
		output, err := scanner.ScanPath(ctx, os.Args[1])
		if err != nil {
			log.Printf("Failed to scan path: %v", err)
		} else {
			printResults(output)
		}
	}

	// Example 2: Scan a string containing potential secrets
	fmt.Println("\n=== Scanning String Content ===")
	testContent := `
	# Example configuration file
	DATABASE_URL=postgres://user:password123@localhost:5432/mydb
	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	`

	output, err := scanner.ScanString(ctx, testContent)
	if err != nil {
		log.Printf("Failed to scan string: %v", err)
	} else {
		printResults(output)
	}

	// Example 3: Scan specific URLs
	fmt.Println("\n=== Scanning URLs ===")
	urls := []string{
		"https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/README.md",
	}

	output, err = scanner.ScanURLs(ctx, urls)
	if err != nil {
		log.Printf("Failed to scan URLs: %v", err)
	} else {
		printResults(output)
	}
}

func printResults(output *export.ScanOutput) {
	fmt.Printf("Scan completed:\n")
	fmt.Printf("  Bytes scanned: %d\n", output.Metrics.BytesScanned)
	fmt.Printf("  Chunks scanned: %d\n", output.Metrics.ChunksScanned)
	fmt.Printf("  Verified secrets: %d\n", output.Metrics.VerifiedSecretsFound)
	fmt.Printf("  Unverified secrets: %d\n", output.Metrics.UnverifiedSecretsFound)

	if len(output.Results) > 0 {
		fmt.Printf("\nSecrets found:\n")
		for i, result := range output.Results {
			fmt.Printf("  %d. [%s] %s\n", i+1, result.DetectorName, result.Redacted)
			fmt.Printf("     Verified: %v\n", result.Verified)
			if result.VerificationError != nil {
				fmt.Printf("     Verification Error: %v\n", result.VerificationError)
			}
		}
	} else {
		fmt.Println("No secrets found.")
	}
}
