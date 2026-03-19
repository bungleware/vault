package handlers

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"

	_ "github.com/mattn/go-sqlite3"
)

type InstanceHandler struct {
	svc     service.InstanceService
	dataDir string
	wsHub   *WSHub
}

func NewInstanceHandler(svc service.InstanceService, dataDir string, wsHub *WSHub) *InstanceHandler {
	return &InstanceHandler{
		svc:     svc,
		dataDir: dataDir,
		wsHub:   wsHub,
	}
}

type ExportManifest struct {
	Version      string    `json:"version"`
	AppVersion   string    `json:"app_version"`
	InstanceName string    `json:"instance_name"`
	CreatedAt    time.Time `json:"created_at"`
}

func (h *InstanceHandler) GetExportSize(w http.ResponseWriter, r *http.Request) error {
	var totalBytes int64

	dbPath := h.svc.GetDBPath()
	if info, err := os.Stat(dbPath); err == nil {
		totalBytes += info.Size()
	}
	if info, err := os.Stat(dbPath + "-wal"); err == nil {
		totalBytes += info.Size()
	}

	projectsDir := filepath.Join(h.dataDir, "projects")
	filepath.Walk(projectsDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalBytes += info.Size()
		}
		return nil
	})

	return httputil.OKResult(w, map[string]int64{"size_bytes": totalBytes})
}

func (h *InstanceHandler) ExportInstance(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	instanceInfo, err := h.svc.GetInstanceSettings(ctx)
	if err != nil {
		return apperr.NewInternal("failed to get instance info", err)
	}

	// Use a dedicated read-only connection for checkpoint: ForceCheckpoint(TRUNCATE) deadlocks with the pool
	dbPath := h.svc.GetDBPath()
	tmpDB, err := sql.Open("sqlite3", fmt.Sprintf("%s?_journal_mode=WAL&mode=ro", dbPath))
	if err != nil {
		return apperr.NewInternal("failed to open database for export", err)
	}
	tmpDB.SetMaxOpenConns(1)
	tmpDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	tmpDB.Close()

	filename := fmt.Sprintf("vault-backup-%s-%d.zip",
		instanceInfo.Name, time.Now().Unix())
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := ExportManifest{
		Version:      "1.0",
		AppVersion:   "v0.0.1",
		InstanceName: instanceInfo.Name,
		CreatedAt:    time.Now().UTC(),
	}
	manifestJSON, _ := json.Marshal(manifest)

	totalFiles := 2 // manifest.json + vault.db
	if _, err := os.Stat(dbPath + "-wal"); err == nil {
		totalFiles++
	}
	projectsDir := filepath.Join(h.dataDir, "projects")
	if _, err := os.Stat(projectsDir); err == nil {
		filepath.Walk(projectsDir, func(_ string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				totalFiles++
			}
			return nil
		})
	}

	currentFile := 0
	sendProgress := func(filename string) {
		currentFile++
		h.sendExportProgress(userID, currentFile, totalFiles, filename)
	}

	manifestFile, err := zw.Create("manifest.json")
	if err != nil {
		return apperr.NewInternal("failed to create manifest in ZIP", err)
	}
	manifestFile.Write(manifestJSON)
	sendProgress("manifest.json")

	dbFile, err := os.Open(dbPath)
	if err == nil {
		defer dbFile.Close()
		if zipFile, err := zw.Create("vault.db"); err == nil {
			io.Copy(zipFile, dbFile)
		}
	}
	sendProgress("vault.db")

	walPath := dbPath + "-wal"
	if walFile, err := os.Open(walPath); err == nil {
		defer walFile.Close()
		if zipFile, err := zw.Create("vault.db-wal"); err == nil {
			io.Copy(zipFile, walFile)
		}
		sendProgress("vault.db-wal")
	}

	if _, err := os.Stat(projectsDir); err == nil {
		h.addDirToZip(zw, projectsDir, "projects", sendProgress)
	}

	return nil
}

func (h *InstanceHandler) addDirToZip(zw *zip.Writer, dir string, prefix string, onFile func(string)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(dir, path)
		zipPath := filepath.Join(prefix, rel)

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		zipFile, err := zw.Create(zipPath)
		if err != nil {
			return nil
		}

		io.Copy(zipFile, file)
		if onFile != nil {
			onFile(zipPath)
		}
		return nil
	})
}

func (h *InstanceHandler) sendExportProgress(userID int, current, total int, filename string) {
	if h.wsHub == nil {
		return
	}
	h.wsHub.SendToUser(int64(userID), WSMessage{
		Type: "export_progress",
		Payload: map[string]interface{}{
			"current":  current,
			"total":    total,
			"filename": filename,
		},
	})
}

func (h *InstanceHandler) sendImportProgress(userID int, stage string, current, total int, filename string) {
	if h.wsHub == nil {
		return
	}
	h.wsHub.SendToUser(int64(userID), WSMessage{
		Type: "import_progress",
		Payload: map[string]interface{}{
			"stage":    stage,
			"current":  current,
			"total":    total,
			"filename": filename,
		},
	})
}

func (h *InstanceHandler) ImportInstance(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return apperr.NewBadRequest("failed to parse form")
	}

	file, _, err := r.FormFile("backup")
	if err != nil {
		return apperr.NewBadRequest("no backup file provided")
	}
	defer file.Close()

	h.sendImportProgress(userID, "uploading", 0, 0, "")

	tmpZip, err := os.CreateTemp(h.dataDir, "vault-import-*.zip")
	if err != nil {
		return apperr.NewInternal("failed to create temp file", err)
	}
	defer os.Remove(tmpZip.Name())

	if _, err := io.Copy(tmpZip, file); err != nil {
		return apperr.NewInternal("failed to save backup file", err)
	}
	tmpZip.Close()

	h.sendImportProgress(userID, "extracting", 0, 0, "")

	zr, err := zip.OpenReader(tmpZip.Name())
	if err != nil {
		return apperr.NewBadRequest("invalid ZIP file")
	}
	defer zr.Close()

	totalFiles := len(zr.File)
	hasManifest := false
	hasDB := false
	tmpExtractDir, err := os.MkdirTemp(h.dataDir, "vault-extract-*")
	if err != nil {
		return apperr.NewInternal("failed to create temp directory", err)
	}
	defer os.RemoveAll(tmpExtractDir)

	for i, f := range zr.File {
		if f.Name == "manifest.json" {
			hasManifest = true
		}
		if f.Name == "vault.db" {
			hasDB = true
		}

		if err := h.extractZipFile(f, tmpExtractDir); err != nil {
			return apperr.NewBadRequest("failed to extract backup")
		}
		h.sendImportProgress(userID, "extracting", i+1, totalFiles, f.Name)
	}

	if !hasManifest || !hasDB {
		return apperr.NewBadRequest("invalid backup: missing manifest or database")
	}

	h.sendImportProgress(userID, "replacing", 0, 0, "")

	if err := h.svc.ForceCheckpoint(); err != nil {
		return apperr.NewInternal("failed to prepare current database", err)
	}

	h.svc.CloseDB()

	dbPath := h.svc.GetDBPath()
	newDBPath := filepath.Join(tmpExtractDir, "vault.db")

	if err := os.Rename(newDBPath, dbPath); err != nil {
		return apperr.NewInternal("failed to replace database", err)
	}

	projectsDir := filepath.Join(h.dataDir, "projects")
	tmpProjectsDir := filepath.Join(tmpExtractDir, "projects")

	if _, err := os.Stat(tmpProjectsDir); err == nil {
		oldProjectsDir := filepath.Join(h.dataDir, "projects.backup")
		os.RemoveAll(oldProjectsDir)
		if err := os.Rename(projectsDir, oldProjectsDir); err == nil {
			if err := os.Rename(tmpProjectsDir, projectsDir); err != nil {
				os.RemoveAll(projectsDir)
				os.Rename(oldProjectsDir, projectsDir)
				return apperr.NewInternal("failed to replace projects", err)
			}
			os.RemoveAll(oldProjectsDir)
		}
	}

	if err := h.svc.ReconnectDB(); err != nil {
		return apperr.NewInternal("failed to reconnect database", err)
	}

	if err := h.svc.InvalidateSessions(ctx); err != nil {
		return apperr.NewInternal("failed to invalidate sessions", err)
	}

	return httputil.OKResult(w, map[string]string{"status": "success"})
}

func (h *InstanceHandler) extractZipFile(f *zip.File, dest string) error {
	path := filepath.Join(dest, f.Name)

	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("invalid file path in archive: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, f.FileInfo().Mode())
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	w, err := os.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, rc)
	return err
}

func (h *InstanceHandler) ResetInstance(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	type NewAdminRequest struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type ResetRequest struct {
		ConfirmName string           `json:"confirm_name"`
		NewAdmin    *NewAdminRequest `json:"new_admin,omitempty"`
	}

	req, err := httputil.DecodeJSON[ResetRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request")
	}

	instanceInfo, err := h.svc.GetInstanceSettings(ctx)
	if err != nil {
		return apperr.NewInternal("failed to get instance info", err)
	}

	if req.ConfirmName != instanceInfo.Name {
		return apperr.NewBadRequest("instance name does not match")
	}

	h.svc.CloseDB()

	dbPath := h.svc.GetDBPath()
	os.Remove(dbPath)
	os.Remove(dbPath + "-shm")
	os.Remove(dbPath + "-wal")

	projectsDir := filepath.Join(h.dataDir, "projects")
	os.RemoveAll(projectsDir)
	os.MkdirAll(projectsDir, 0755)

	if err := h.svc.ReconnectDB(); err != nil {
		return apperr.NewInternal("failed to reinitialize database", err)
	}

	if req.NewAdmin != nil {
		if req.NewAdmin.Username == "" || req.NewAdmin.Email == "" || req.NewAdmin.Password == "" {
			return apperr.NewBadRequest("new admin credentials are required")
		}

		passwordHash, err := auth.HashPassword(req.NewAdmin.Password)
		if err != nil {
			return apperr.NewInternal("failed to hash password", err)
		}

		newUser, err := h.svc.CreateUser(ctx, sqlc.CreateUserParams{
			Username:     req.NewAdmin.Username,
			Email:        req.NewAdmin.Email,
			PasswordHash: passwordHash,
			IsAdmin:      true,
			IsOwner:      true,
		})
		if err != nil {
			return apperr.NewInternal("failed to create admin user", err)
		}

		if err := h.svc.CreateUserPreferences(ctx, sqlc.CreateUserPreferencesParams{
			UserID:         newUser.ID,
			DefaultQuality: "lossy",
		}); err != nil {
			return apperr.NewInternal("failed to create user preferences", err)
		}
	}

	if err := h.svc.InvalidateSessions(ctx); err != nil {
		return apperr.NewInternal("failed to invalidate sessions", err)
	}

	return httputil.OKResult(w, map[string]string{"status": "success"})
}
