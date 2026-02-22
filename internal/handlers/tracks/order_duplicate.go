package tracks

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/ids"
)

type UpdateTrackOrderRequest struct {
	TrackOrders []struct {
		ID    int64 `json:"id"`
		Order int64 `json:"order"`
	} `json:"track_orders"`
}

func (h *TracksHandler) UpdateTracksOrder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[UpdateTrackOrderRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	if len(req.TrackOrders) == 0 {
		return httputil.NoContentResult(w)
	}

	firstTrack, err := h.db.GetTrackByID(ctx, req.TrackOrders[0].ID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	project, err := h.db.GetProjectByID(ctx, firstTrack.ProjectID)
	if err != nil {
		return apperr.NewNotFound("project not found")
	}

	canEdit := project.UserID == int64(userID)
	if !canEdit {
		share, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  int64(userID),
		})
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewForbidden("access denied")
		}
		if err != nil {
			return apperr.NewInternal("failed to check permissions", err)
		}
		if !share.CanEdit {
			return apperr.NewForbidden("editing not allowed")
		}
	}

	for _, trackOrder := range req.TrackOrders {
		track, err := h.db.GetTrackByID(ctx, trackOrder.ID)
		if err != nil || track.ProjectID != project.ID {
			return apperr.NewBadRequest("all tracks must belong to the same project")
		}
	}

	for _, trackOrder := range req.TrackOrders {
		err := h.db.UpdateTrackOrder(ctx, sqlc.UpdateTrackOrderParams{
			TrackOrder: trackOrder.Order,
			ID:         trackOrder.ID,
		})
		if err != nil {
			return apperr.NewInternal("failed to update track order", err)
		}
	}

	return httputil.NoContentResult(w)
}

func (h *TracksHandler) DuplicateTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")
	ctx := r.Context()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.NewInternal("failed to start transaction", err)
	}
	defer tx.Rollback()

	queries := sqlc.New(tx)

	originalTrack, err := queries.GetTrackByPublicID(ctx, sqlc.GetTrackByPublicIDParams{
		PublicID: publicID,
		UserID:   int64(userID),
	})
	if err := httputil.HandleDBError(err, "track not found", "failed to fetch track"); err != nil {
		return err
	}

	newPublicID, err := ids.NewPublicID()
	if err != nil {
		return apperr.NewInternal("failed to generate track id", err)
	}

	newTitle := originalTrack.Title + " (Copy)"
	duplicateTrack, err := queries.CreateTrack(ctx, sqlc.CreateTrackParams{
		UserID:    int64(userID),
		ProjectID: originalTrack.ProjectID,
		Title:     newTitle,
		Artist:    originalTrack.Artist,
		Album:     originalTrack.Album,
		PublicID:  newPublicID,
	})
	if err != nil {
		return apperr.NewInternal("failed to create duplicate track", err)
	}

	versions, err := queries.ListTrackVersions(ctx, originalTrack.ID)
	if err != nil {
		return apperr.NewInternal("failed to list versions", err)
	}

	var newActiveVersionID int64

	for _, version := range versions {
		newVersion, err := queries.CreateTrackVersion(ctx, sqlc.CreateTrackVersionParams{
			TrackID:         duplicateTrack.ID,
			VersionName:     version.VersionName,
			Notes:           version.Notes,
			DurationSeconds: version.DurationSeconds,
			VersionOrder:    version.VersionOrder,
		})
		if err != nil {
			return apperr.NewInternal("failed to create duplicate version", err)
		}

		if originalTrack.ActiveVersionID.Valid && originalTrack.ActiveVersionID.Int64 == version.ID {
			newActiveVersionID = newVersion.ID
		}

		files, err := queries.ListTrackFilesByVersion(ctx, version.ID)
		if err != nil {
			return apperr.NewInternal("failed to list track files", err)
		}

		for _, file := range files {
			oldPath := file.FilePath
			oldDir := filepath.Dir(oldPath)
			fileName := filepath.Base(oldPath)
			newDir := strings.Replace(oldDir, fmt.Sprintf("tracks/%d/versions/%d", originalTrack.ID, version.ID),
				fmt.Sprintf("tracks/%d/versions/%d", duplicateTrack.ID, newVersion.ID), 1)
			newPath := filepath.Join(newDir, fileName)

			if err := os.MkdirAll(newDir, 0o755); err != nil {
				return apperr.NewInternal("failed to create version directory", err)
			}

			if err := copyFile(oldPath, newPath); err != nil {
				return apperr.NewInternal("failed to copy file", err)
			}

			_, err := queries.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
				VersionID:         newVersion.ID,
				Quality:           file.Quality,
				FilePath:          newPath,
				FileSize:          file.FileSize,
				Format:            file.Format,
				Bitrate:           file.Bitrate,
				ContentHash:       file.ContentHash,
				TranscodingStatus: file.TranscodingStatus,
				OriginalFilename:  file.OriginalFilename,
			})
			if err != nil {
				return apperr.NewInternal("failed to create file record", err)
			}
		}
	}

	if newActiveVersionID != 0 {
		err = queries.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
			ActiveVersionID: sql.NullInt64{Int64: newActiveVersionID, Valid: true},
			ID:              duplicateTrack.ID,
		})
		if err != nil {
			return apperr.NewInternal("failed to set active version", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return apperr.NewInternal("failed to finalize duplication", err)
	}

	return httputil.CreatedResult(w, convertTrack(duplicateTrack))
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}
