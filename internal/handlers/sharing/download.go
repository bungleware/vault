package sharing

import (
	"archive/zip"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/service"
)

// sanitizeFilename strips characters that could break HTTP header values.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '"' {
			return -1
		}
		return r
	}, s)
}

func (h *SharingHandler) DownloadShared(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	ctx := r.Context()

	// Try track download first.
	trackResult, err := h.svc.GetTrackForDownload(ctx, token)
	if err == nil {
		if err := h.validateFilePath(trackResult.FilePath); err != nil {
			return err
		}
		h.svc.IncrementTrackAccessCount(ctx, trackResult.TokenID)
		w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(trackResult.Title+"."+trackResult.Format)+"\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, trackResult.FilePath)
		return nil
	}
	if !errors.Is(err, service.ErrNotFound) {
		return mapSharingErr(err)
	}

	// Fall back to project download.
	projectResult, err := h.svc.GetProjectForDownload(ctx, token)
	if err != nil {
		return mapSharingErr(err)
	}

	h.svc.IncrementProjectAccessCount(ctx, projectResult.TokenID)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(projectResult.ProjectName+".zip")+"\"")

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	for _, track := range projectResult.Tracks {
		file, err := os.Open(track.FilePath)
		if err != nil {
			continue
		}
		zipEntry, err := zipWriter.Create(track.Title + "." + track.Format)
		if err != nil {
			file.Close()
			continue
		}
		_, err = io.Copy(zipEntry, file)
		file.Close()
		if err != nil {
			continue
		}
	}
	return nil
}

func (h *SharingHandler) DownloadSharedProjectTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	trackPublicID := r.PathValue("trackId")
	if token == "" || trackPublicID == "" {
		return apperr.NewBadRequest("token and trackId required")
	}

	result, err := h.svc.GetProjectTrackForDownload(r.Context(), token, trackPublicID)
	if err != nil {
		return mapSharingErr(err)
	}
	if err := h.validateFilePath(result.FilePath); err != nil {
		return err
	}
	h.svc.IncrementProjectAccessCount(r.Context(), result.TokenID)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(result.Title+"."+result.Format)+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, result.FilePath)
	return nil
}
