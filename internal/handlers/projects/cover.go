package projects

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/middleware"
	"bungleware/vault/internal/service"
)

func (h *ProjectsHandler) UploadProjectCover(w http.ResponseWriter, r *http.Request) error {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		if !middleware.SignedURLValid(r.Context()) {
			return apperr.NewUnauthorized("user not found in context")
		}
		signedUserID := r.URL.Query().Get("user_id")
		if signedUserID == "" {
			return apperr.NewUnauthorized("user not found in context")
		}
		parsed, err := strconv.Atoi(signedUserID)
		if err != nil {
			return apperr.NewBadRequest("invalid user_id")
		}
		userID = parsed
	}

	publicID := r.PathValue("id")

	if err := r.ParseMultipartForm(maxCoverUploadSize); err != nil {
		return apperr.NewBadRequest("failed to parse form")
	}

	file, header, err := r.FormFile("cover")
	if err != nil {
		return apperr.NewBadRequest("cover file is required")
	}
	defer file.Close()

	project, err := h.service.UploadCover(r.Context(), service.UploadCoverInput{
		UserID:   int64(userID),
		PublicID: publicID,
		Filename: header.Filename,
		Reader:   file,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.NewNotFound("project not found")
	}
	if err != nil {
		if err.Error() == "unsupported cover format" {
			return apperr.NewBadRequest(err.Error())
		}
		return apperr.NewInternal("failed to upload cover", err)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	return httputil.OKResult(w, shared.ConvertProject(project))
}

func (h *ProjectsHandler) DeleteProjectCover(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	project, err := h.service.DeleteCover(r.Context(), publicID, int64(userID))
	if err := httputil.HandleDBError(err, "project not found", "failed to delete cover"); err != nil {
		return err
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	return httputil.OKResult(w, shared.ConvertProject(project))
}

func (h *ProjectsHandler) GetProjectCover(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")
	ctx := r.Context()

	size := r.URL.Query().Get("size")

	stream, err := h.service.GetCoverStream(ctx, publicID, int64(userID), size)
	if err == nil {
		defer stream.Reader.Close()
		w.Header().Set("Content-Type", stream.MimeType)
		w.Header().Set("Content-Length", strconv.FormatInt(stream.Size, 10))
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if stream.HasUpdatedAt {
			w.Header().Set("Last-Modified", stream.UpdatedAt.UTC().Format(http.TimeFormat))
		}
		if _, err := io.Copy(w, stream.Reader); err != nil {
			slog.Debug("failed to stream project cover", "error", err)
		}
		return nil
	}

	project, err := h.db.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "project not found", "failed to get project"); err != nil {
		return err
	}

	hasAccess := false

	projectShares, err := h.db.ListUsersProjectIsSharedWith(ctx, project.ID)
	if err == nil {
		for _, share := range projectShares {
			if share.SharedTo == int64(userID) {
				hasAccess = true
				break
			}
		}
	}

	if !hasAccess {
		tracks, err := h.db.ListTracksByProjectID(ctx, project.ID)
		if err == nil {
			for _, track := range tracks {
				trackShares, err := h.db.ListUsersTrackIsSharedWith(ctx, track.ID)
				if err == nil {
					for _, share := range trackShares {
						if share.SharedTo == int64(userID) {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
		}
	}

	if !hasAccess {
		return apperr.NewForbidden("access denied")
	}

	if !project.CoverArtPath.Valid {
		return apperr.NewNotFound("cover not found")
	}

	stream, err = h.service.GetCoverStream(ctx, publicID, project.UserID, size)
	if err := httputil.HandleDBError(err, "cover not found", "failed to get cover"); err != nil {
		return err
	}
	defer stream.Reader.Close()

	w.Header().Set("Content-Type", stream.MimeType)
	w.Header().Set("Content-Length", strconv.FormatInt(stream.Size, 10))
	// Use aggressive caching since URL includes timestamp for cache busting
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	if stream.HasUpdatedAt {
		w.Header().Set("Last-Modified", stream.UpdatedAt.UTC().Format(http.TimeFormat))
	}

	if _, err := io.Copy(w, stream.Reader); err != nil {
		slog.Debug("failed to stream project cover", "error", err)
	}
	return nil
}
