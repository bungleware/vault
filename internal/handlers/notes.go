package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/tracks"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type NotesHandler struct {
	notesService  service.NotesService
	tracksService service.TracksService
}

func NewNotesHandler(notesService service.NotesService, tracksService service.TracksService) *NotesHandler {
	return &NotesHandler{
		notesService:  notesService,
		tracksService: tracksService,
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

	track, err := h.notesService.GetTrackByPublicID(ctx, trackPublicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to get track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, userID64)
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	notes, err := h.notesService.GetTrackNotes(ctx, track.ID)
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

	return httputil.OKResult(w, response)
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

	project, err := h.notesService.GetProjectByPublicID(r.Context(), projectPublicID, userID64)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewNotFound("project not found")
		}
		return apperr.NewInternal(err.Error(), err)
	}

	notes, err := h.notesService.GetProjectNotes(r.Context(), project.ID)
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

	return httputil.OKResult(w, response)
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

	track, err := h.notesService.GetTrackByPublicID(ctx, trackPublicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to get track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, userID64)
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	note, err := h.notesService.UpsertTrackNote(r.Context(), sqlc.UpsertTrackNoteParams{
		UserID:     userID64,
		TrackID:    sql.NullInt64{Int64: track.ID, Valid: true},
		Content:    req.Content,
		AuthorName: req.AuthorName,
	})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	return httputil.OKResult(w, NoteResponse{
		ID:         note.ID,
		UserID:     note.UserID,
		Content:    note.Content,
		AuthorName: note.AuthorName,
		CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
		UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
		IsOwner:    true,
	})
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

	project, err := h.notesService.GetProjectByPublicID(r.Context(), projectPublicID, userID64)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewNotFound("project not found")
		}
		return apperr.NewInternal(err.Error(), err)
	}

	note, err := h.notesService.UpsertProjectNote(r.Context(), sqlc.UpsertProjectNoteParams{
		UserID:     userID64,
		ProjectID:  sql.NullInt64{Int64: project.ID, Valid: true},
		Content:    req.Content,
		AuthorName: req.AuthorName,
	})
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	return httputil.OKResult(w, NoteResponse{
		ID:         note.ID,
		UserID:     note.UserID,
		Content:    note.Content,
		AuthorName: note.AuthorName,
		CreatedAt:  httputil.FormatNullTimeString(note.CreatedAt),
		UpdatedAt:  httputil.FormatNullTimeString(note.UpdatedAt),
		IsOwner:    true,
	})
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

	err = h.notesService.DeleteNote(r.Context(), noteID, userID64)
	if err != nil {
		return apperr.NewInternal(err.Error(), err)
	}

	return httputil.NoContentResult(w)
}
