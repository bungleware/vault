package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"path/filepath"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/transcoding"
)

func main() {
	// Parse command line flags
	dataDir := flag.String("data-dir", "./data", "Path to data directory")
	dryRun := flag.Bool("dry-run", false, "Show what would be done without making changes")
	verbose := flag.Bool("verbose", false, "Show verbose output")
	flag.Parse()

	log.Println("=== Waveform Generator for Existing Tracks ===")
	log.Printf("Data directory: %s", *dataDir)
	log.Printf("Dry run: %v", *dryRun)
	log.Println()

	// Initialize database
	database, err := db.New(db.Config{
		DataDir:        *dataDir,
		DBFile:         "vault.db",
		MigrationsPath: "migrations",
	})
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	log.Println("Database connected successfully")

	ctx := context.Background()

	// Get all track files that don't have waveform data
	rows, err := database.Queries.ListAllTrackFiles(ctx)
	if err != nil {
		log.Fatalf("Failed to query track files: %v", err)
	}

	var filesToProcess []sqlc.TrackFile
	var filesWithWaveform int
	var filesWithoutSource int
	var nonLossyFiles int

	for _, file := range rows {
		// Only process lossy (MP3) files - they're the ones shown in the player
		if file.Quality != "lossy" {
			nonLossyFiles++
			if *verbose {
				log.Printf("  - File ID %d (%s): Skipping non-lossy file", file.ID, file.Quality)
			}
			continue
		}

		// Check if waveform exists
		if file.Waveform.Valid && file.Waveform.String != "" {
			filesWithWaveform++
			if *verbose {
				log.Printf("  ✓ File ID %d already has waveform", file.ID)
			}
			continue
		}

		// We need the source file to generate waveform
		// Get the source file for this version
		sourceFile, err := database.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: file.VersionID,
			Quality:   "source",
		})
		if err != nil {
			if *verbose {
				log.Printf("  ✗ File ID %d (version %d): No source file found, skipping", file.ID, file.VersionID)
			}
			filesWithoutSource++
			continue
		}

		// Check if source file exists on disk
		if _, err := os.Stat(sourceFile.FilePath); os.IsNotExist(err) {
			if *verbose {
				log.Printf("  ✗ File ID %d (version %d): Source file not found at %s, skipping", file.ID, file.VersionID, sourceFile.FilePath)
			}
			filesWithoutSource++
			continue
		}

		// Add to processing list
		filesToProcess = append(filesToProcess, file)
	}

	log.Println()
	log.Printf("Summary:")
	log.Printf("  Total track files: %d", len(rows))
	log.Printf("  Non-lossy files (skipped): %d", nonLossyFiles)
	log.Printf("  Lossy files with waveform: %d", filesWithWaveform)
	log.Printf("  Files without source: %d", filesWithoutSource)
	log.Printf("  Lossy files to process: %d", len(filesToProcess))
	log.Println()

	if len(filesToProcess) == 0 {
		log.Println("No files to process. All done!")
		return
	}

	if *dryRun {
		log.Println("DRY RUN - Would process the following files:")
		for _, file := range filesToProcess {
			// Get source file
			sourceFile, _ := database.GetTrackFile(ctx, sqlc.GetTrackFileParams{
				VersionID: file.VersionID,
				Quality:   "source",
			})
			log.Printf("  - File ID %d (version %d): %s", file.ID, file.VersionID, sourceFile.FilePath)
		}
		log.Println()
		log.Println("Run without --dry-run to actually generate waveforms")
		return
	}

	// Process each file
	log.Println("Processing files...")
	successCount := 0
	failCount := 0

	for i, file := range filesToProcess {
		log.Printf("[%d/%d] Processing file ID %d...", i+1, len(filesToProcess), file.ID)

		// Get source file
		sourceFile, err := database.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: file.VersionID,
			Quality:   "source",
		})
		if err != nil {
			log.Printf("  ✗ Failed to get source file: %v", err)
			failCount++
			continue
		}

		// Generate waveform
		log.Printf("  Generating waveform from: %s", filepath.Base(sourceFile.FilePath))
		waveformJSON, err := transcoding.GenerateWaveformJSON(sourceFile.FilePath, 200)
		if err != nil {
			log.Printf("  ✗ Failed to generate waveform: %v", err)
			failCount++
			continue
		}

		// Save to database
		err = database.UpdateWaveform(ctx, sqlc.UpdateWaveformParams{
			Waveform: sql.NullString{String: waveformJSON, Valid: true},
			ID:       file.ID,
		})
		if err != nil {
			log.Printf("  ✗ Failed to save waveform: %v", err)
			failCount++
			continue
		}

		log.Printf("  ✓ Success!")
		successCount++
	}

	log.Println()
	log.Printf("=== Results ===")
	log.Printf("  Successful: %d", successCount)
	log.Printf("  Failed: %d", failCount)
	log.Printf("  Total: %d", len(filesToProcess))

	if successCount > 0 {
		log.Println()
		log.Println("✓ Waveform generation complete!")
	}
}
