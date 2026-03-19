package service

import (
	"context"
	"database/sql"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type NotesService interface {
	GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error)
	GetProjectByPublicID(ctx context.Context, publicID string, userID int64) (sqlc.GetProjectByPublicIDRow, error)
	GetTrackNotes(ctx context.Context, trackID int64) ([]sqlc.Note, error)
	GetProjectNotes(ctx context.Context, projectID int64) ([]sqlc.Note, error)
	UpsertTrackNote(ctx context.Context, params sqlc.UpsertTrackNoteParams) (sqlc.Note, error)
	UpsertProjectNote(ctx context.Context, params sqlc.UpsertProjectNoteParams) (sqlc.Note, error)
	DeleteNote(ctx context.Context, noteID, userID int64) error
}

type notesService struct {
	db *db.DB
}

func NewNotesService(database *db.DB) NotesService {
	return &notesService{db: database}
}

func (s *notesService) GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error) {
	return s.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
}

func (s *notesService) GetProjectByPublicID(ctx context.Context, publicID string, userID int64) (sqlc.GetProjectByPublicIDRow, error) {
	return s.db.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: publicID,
		UserID:   userID,
	})
}

func (s *notesService) GetTrackNotes(ctx context.Context, trackID int64) ([]sqlc.Note, error) {
	return s.db.GetNotesByTrack(ctx, sql.NullInt64{Int64: trackID, Valid: true})
}

func (s *notesService) GetProjectNotes(ctx context.Context, projectID int64) ([]sqlc.Note, error) {
	return s.db.GetNotesByProject(ctx, sql.NullInt64{Int64: projectID, Valid: true})
}

func (s *notesService) UpsertTrackNote(ctx context.Context, params sqlc.UpsertTrackNoteParams) (sqlc.Note, error) {
	return s.db.UpsertTrackNote(ctx, params)
}

func (s *notesService) UpsertProjectNote(ctx context.Context, params sqlc.UpsertProjectNoteParams) (sqlc.Note, error) {
	return s.db.UpsertProjectNote(ctx, params)
}

func (s *notesService) DeleteNote(ctx context.Context, noteID, userID int64) error {
	return s.db.DeleteNote(ctx, sqlc.DeleteNoteParams{ID: noteID, UserID: userID})
}
