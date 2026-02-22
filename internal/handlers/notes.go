package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/tracks"
	"bungleware/vault/internal/httputil"
)

type NotesHandler struct {
	db *db.DB
}

func NewNotesHandler(database *db.DB) *NotesHandler {
	return &NotesHandler{
		db: database,
	}
}

func (h *NotesHandler) GetTrackNotes(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}
	userID64 := int64(userID)

	trackPublicID := r.PathValue("trackId")
	if trackPublicID == "" {
		return apperr.NewBadRequest("track ID is required")
	}

	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to get track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.db, track.ID, track.ProjectID, userID64)
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	notes, err := h.db.GetNotesByTrack(r.Context(), sql.NullInt64{Int64: track.ID, Valid: true})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	response := make([]NoteResponse, len(notes))
	for i, note := range notes {
		response[i] = NoteResponse{
			ID:         note.ID,
			UserID:     note.UserID,
			Content:    note.Content,
			AuthorName: note.AuthorName,
			CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
			UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
			IsOwner:    note.UserID == userID64,
		}
	}

	httputil.OK(w, response)
	return nil
}

func (h *NotesHandler) GetProjectNotes(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}
	userID64 := int64(userID)

	projectPublicID := r.PathValue("projectId")
	if projectPublicID == "" {
		return apperr.NewBadRequest("project ID is required")
	}

	project, err := h.db.GetProjectByPublicID(r.Context(), sqlc.GetProjectByPublicIDParams{
		PublicID: projectPublicID,
		UserID:   userID64,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewNotFound("project not found")
		}
		return apperr.NewInternal(err.Error(), err)
	}

	notes, err := h.db.GetNotesByProject(r.Context(), sql.NullInt64{Int64: project.ID, Valid: true})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	response := make([]NoteResponse, len(notes))
	for i, note := range notes {
		response[i] = NoteResponse{
			ID:         note.ID,
			UserID:     note.UserID,
			Content:    note.Content,
			AuthorName: note.AuthorName,
			CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
			UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
			IsOwner:    note.UserID == userID64,
		}
	}

	httputil.OK(w, response)
	return nil
}

func (h *NotesHandler) UpsertTrackNote(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}
	userID64 := int64(userID)

	trackPublicID := r.PathValue("trackId")
	if trackPublicID == "" {
		return apperr.NewBadRequest("track ID is required")
	}

	req, err := httputil.DecodeJSON[UpsertNoteRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to get track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.db, track.ID, track.ProjectID, userID64)
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	note, err := h.db.UpsertTrackNote(r.Context(), sqlc.UpsertTrackNoteParams{
		UserID:     userID64,
		TrackID:    sql.NullInt64{Int64: track.ID, Valid: true},
		Content:    req.Content,
		AuthorName: req.AuthorName,
	})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	response := NoteResponse{
		ID:         note.ID,
		UserID:     note.UserID,
		Content:    note.Content,
		AuthorName: note.AuthorName,
		CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
		UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
		IsOwner:    true,
	}

	httputil.OK(w, response)
	return nil
}

func (h *NotesHandler) UpsertProjectNote(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}
	userID64 := int64(userID)

	projectPublicID := r.PathValue("projectId")
	if projectPublicID == "" {
		return apperr.NewBadRequest("project ID is required")
	}

	req, err := httputil.DecodeJSON[UpsertNoteRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	project, err := h.db.GetProjectByPublicID(r.Context(), sqlc.GetProjectByPublicIDParams{
		PublicID: projectPublicID,
		UserID:   userID64,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewNotFound("project not found")
		}
		return apperr.NewInternal(err.Error(), err)
	}

	note, err := h.db.UpsertProjectNote(r.Context(), sqlc.UpsertProjectNoteParams{
		UserID:     userID64,
		ProjectID:  sql.NullInt64{Int64: project.ID, Valid: true},
		Content:    req.Content,
		AuthorName: req.AuthorName,
	})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	response := NoteResponse{
		ID:         note.ID,
		UserID:     note.UserID,
		Content:    note.Content,
		AuthorName: note.AuthorName,
		CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
		UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
		IsOwner:    true,
	}

	httputil.OK(w, response)
	return nil
}

func (h *NotesHandler) DeleteNote(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}
	userID64 := int64(userID)

	noteID, err := httputil.PathInt64(r, "noteId")
	if err != nil {
		return err
	}

	err = h.db.DeleteNote(r.Context(), sqlc.DeleteNoteParams{
		ID:     noteID,
		UserID: userID64,
	})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	httputil.NoContent(w)
	return nil
}
