package transcoding

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type Job struct {
	TrackFileID   int64
	VersionID     int64
	TrackPublicID string
	UserID        int64
	SourcePath    string
	OutputPath    string
}

type TranscodingNotifier interface {
	NotifyTranscodingUpdate(userID int64, trackPublicID string, versionID int64, status string)
}

type Transcoder struct {
	db       *db.DB
	queue    chan Job
	workers  int
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	notifier TranscodingNotifier
}

func NewTranscoder(database *db.DB, workers int) *Transcoder {
	ctx, cancel := context.WithCancel(context.Background())
	return &Transcoder{
		db:      database,
		queue:   make(chan Job, 100),
		workers: workers,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (t *Transcoder) SetNotifier(n TranscodingNotifier) {
	t.notifier = n
}

func (t *Transcoder) Start() {
	log.Printf("Starting %d transcoding workers", t.workers)
	for i := 0; i < t.workers; i++ {
		t.wg.Add(1)
		go t.worker(i)
	}
}

func (t *Transcoder) Stop() {
	log.Println("Stopping transcoding workers...")
	t.cancel()
	close(t.queue)
	t.wg.Wait()
	log.Println("All transcoding workers stopped")
}

func (t *Transcoder) QueueJob(job Job) {
	select {
	case t.queue <- job:
		log.Printf("Queued transcoding job for version %d", job.VersionID)
	case <-t.ctx.Done():
		log.Println("Cannot queue job: transcoder is shutting down")
	}
}

func (t *Transcoder) worker(id int) {
	defer t.wg.Done()
	log.Printf("Worker %d started", id)

	for {
		select {
		case job, ok := <-t.queue:
			if !ok {
				log.Printf("Worker %d: queue closed, exiting", id)
				return
			}
			log.Printf("Worker %d: processing job for version %d", id, job.VersionID)
			t.processJob(job)
		case <-t.ctx.Done():
			log.Printf("Worker %d: context cancelled, exiting", id)
			return
		}
	}
}

func (t *Transcoder) processJob(job Job) {
	ctx := context.Background()

	err := t.db.UpdateTranscodingStatus(ctx, sqlc.UpdateTranscodingStatusParams{
		TranscodingStatus: sql.NullString{String: "processing", Valid: true},
		ID:                job.TrackFileID,
	})
	if err != nil {
		log.Printf("Failed to update transcoding status to processing: %v", err)
		return
	}

	t.notify(job, "processing")

	err = t.transcodeToMP3(job.SourcePath, job.OutputPath)
	if err != nil {
		log.Printf("Transcoding failed for version %d: %v", job.VersionID, err)
		t.db.UpdateTranscodingStatus(ctx, sqlc.UpdateTranscodingStatusParams{
			TranscodingStatus: sql.NullString{String: "failed", Valid: true},
			ID:                job.TrackFileID,
		})
		t.notify(job, "failed")
		return
	}

	if stat, err := os.Stat(job.OutputPath); err == nil {
		if err := t.db.UpdateTrackFileSize(ctx, sqlc.UpdateTrackFileSizeParams{
			FileSize: stat.Size(),
			ID:       job.TrackFileID,
		}); err != nil {
			log.Printf("Failed to update file size for version %d: %v", job.VersionID, err)
		}
	}

	log.Printf("Generating waveform for version %d", job.VersionID)
	waveformJSON, err := GenerateWaveformJSON(job.SourcePath, 200)
	if err != nil {
		log.Printf("Failed to generate waveform for version %d: %v", job.VersionID, err)
		waveformJSON = ""
	} else {
		err = t.db.UpdateWaveform(ctx, sqlc.UpdateWaveformParams{
			Waveform: sql.NullString{String: waveformJSON, Valid: true},
			ID:       job.TrackFileID,
		})
		if err != nil {
			log.Printf("Failed to save waveform to database: %v", err)
		} else {
			log.Printf("Successfully saved waveform for version %d", job.VersionID)
		}
	}

	err = t.db.UpdateTranscodingStatus(ctx, sqlc.UpdateTranscodingStatusParams{
		TranscodingStatus: sql.NullString{String: "completed", Valid: true},
		ID:                job.TrackFileID,
	})
	if err != nil {
		log.Printf("Failed to update transcoding status to completed: %v", err)
		return
	}

	t.notify(job, "completed")

	log.Printf("Successfully transcoded version %d to MP3", job.VersionID)
}

func (t *Transcoder) notify(job Job, status string) {
	if t.notifier != nil {
		t.notifier.NotifyTranscodingUpdate(job.UserID, job.TrackPublicID, job.VersionID, status)
	}
}

func (t *Transcoder) transcodeToMP3(inputPath, outputPath string) error {
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	cmd := exec.Command(
		"ffmpeg",
		"-i", inputPath,
		"-vn",
		"-ar", "44100",
		"-ac", "2",
		"-b:a", "320k",
		"-y",
		outputPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ffmpeg failed: %w, output: %s", err, string(output))
	}

	log.Printf("Transcoded %s to %s", filepath.Base(inputPath), filepath.Base(outputPath))
	return nil
}

type TranscodeVersionInput struct {
	VersionID      int64
	SourceFilePath string
	TrackPublicID  string
	UserID         int64
}

func (t *Transcoder) TranscodeVersion(ctx context.Context, input TranscodeVersionInput) error {
	sourceDir := filepath.Dir(input.SourceFilePath)
	lossyPath := filepath.Join(sourceDir, "lossy.mp3")

	trackFile, err := t.db.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
		VersionID:         input.VersionID,
		Quality:           "lossy",
		FilePath:          lossyPath,
		FileSize:          0,
		Format:            "mp3",
		Bitrate:           sql.NullInt64{Int64: 320000, Valid: true},
		ContentHash:       sql.NullString{},
		TranscodingStatus: sql.NullString{String: "pending", Valid: true},
		OriginalFilename:  sql.NullString{},
	})
	if err != nil {
		return fmt.Errorf("failed to create track file record: %w", err)
	}

	t.QueueJob(Job{
		TrackFileID:   trackFile.ID,
		VersionID:     input.VersionID,
		TrackPublicID: input.TrackPublicID,
		UserID:        input.UserID,
		SourcePath:    input.SourceFilePath,
		OutputPath:    lossyPath,
	})

	return nil
}
