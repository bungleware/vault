package main

import (
	"context"
	"database/sql"
	"flag"
	"log"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "Path to data directory")
	flag.Parse()

	log.Println("=== Clear All Waveforms ===")
	log.Printf("Data directory: %s", *dataDir)
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

	// Get all track files
	rows, err := database.Queries.ListAllTrackFiles(ctx)
	if err != nil {
		log.Fatalf("Failed to query track files: %v", err)
	}

	log.Printf("Found %d track files", len(rows))
	log.Println("Clearing waveforms...")

	count := 0
	for _, file := range rows {
		if file.Waveform.Valid && file.Waveform.String != "" {
			err := database.UpdateWaveform(ctx, sqlc.UpdateWaveformParams{
				Waveform: sql.NullString{Valid: false},
				ID:       file.ID,
			})
			if err != nil {
				log.Printf("Failed to clear waveform for file ID %d: %v", file.ID, err)
			} else {
				count++
			}
		}
	}

	log.Printf("✓ Cleared %d waveforms", count)
}
