package main

import (
	"context"
	"flag"
	"log"

	"bungleware/vault/internal/db"
)

func main() {
	dataDir := flag.String("data-dir", "./data", "Path to data directory")
	flag.Parse()

	log.Println("=== Clear Audio Analysis (BPM & Key) ===")
	log.Printf("Data directory: %s", *dataDir)
	log.Println()

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

	countQuery := `SELECT COUNT(*) FROM tracks WHERE bpm IS NOT NULL OR key IS NOT NULL`
	var countBefore int64
	err = database.DB.QueryRowContext(ctx, countQuery).Scan(&countBefore)
	if err != nil {
		log.Fatalf("Failed to count tracks with analysis: %v", err)
	}

	if countBefore == 0 {
		log.Println("No tracks have BPM or key data to clear.")
		return
	}

	log.Printf("Found %d tracks with BPM and/or key data", countBefore)
	log.Println("Clearing all BPM and key data...")

	// Clear all analysis data
	err = database.Queries.ClearAllTracksAnalysis(ctx)
	if err != nil {
		log.Fatalf("Failed to clear analysis data: %v", err)
	}

	log.Println()
	log.Printf("✓ Successfully cleared analysis data for %d tracks", countBefore)
	log.Println()
	log.Println("You can now re-analyze tracks with improved algorithms using:")
	log.Println("  make detect-bpm")
}
