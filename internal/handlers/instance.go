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
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"

	_ "github.com/mattn/go-sqlite3"
)

type InstanceHandler struct {
	db      *db.DB
	dataDir string
}

func NewInstanceHandler(database *db.DB, dataDir string) *InstanceHandler {
	return &InstanceHandler{
		db:      database,
		dataDir: dataDir,
	}
}

type ExportManifest struct {
	Version      string    `json:"version"`
	AppVersion   string    `json:"app_version"`
	InstanceName string    `json:"instance_name"`
	CreatedAt    time.Time `json:"created_at"`
}

// ExportInstance streams a complete backup as ZIP
func (h *InstanceHandler) ExportInstance(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	user, err := h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil || !user.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	instanceInfo, err := h.db.Queries.GetInstanceSettings(ctx)
	if err != nil {
		return apperr.NewInternal("failed to get instance info", err)
	}

	// Use a dedicated read-only connection for checkpoint: ForceCheckpoint(TRUNCATE) deadlocks with the pool
	dbPath := h.db.GetPath()
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

	manifestFile, err := zw.Create("manifest.json")
	if err != nil {
		return apperr.NewInternal("failed to create manifest in ZIP", err)
	}
	manifestFile.Write(manifestJSON)

	dbFile, err := os.Open(dbPath)
	if err == nil {
		defer dbFile.Close()
		if zipFile, err := zw.Create("vault.db"); err == nil {
			io.Copy(zipFile, dbFile)
		}
	}
	// Include WAL for complete backup
	walPath := dbPath + "-wal"
	if walFile, err := os.Open(walPath); err == nil {
		defer walFile.Close()
		if zipFile, err := zw.Create("vault.db-wal"); err == nil {
			io.Copy(zipFile, walFile)
		}
	}

	projectsDir := filepath.Join(h.dataDir, "projects")
	if _, err := os.Stat(projectsDir); err == nil {
		h.addDirToZip(zw, projectsDir, "projects")
	}

	return nil
}

func (h *InstanceHandler) addDirToZip(zw *zip.Writer, dir string, prefix string) error {
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
			return nil // Skip on error
		}
		defer file.Close()

		zipFile, err := zw.Create(zipPath)
		if err != nil {
			return nil
		}

		io.Copy(zipFile, file)
		return nil
	})
}

// ImportInstance replaces data with uploaded backup
func (h *InstanceHandler) ImportInstance(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	user, err := h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil || !user.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	if err := r.ParseMultipartForm(10 * 1024 * 1024 * 1024); err != nil { // 10GB max
		return apperr.NewBadRequest("failed to parse form")
	}

	file, _, err := r.FormFile("backup")
	if err != nil {
		return apperr.NewBadRequest("no backup file provided")
	}
	defer file.Close()

	tmpZip, err := os.CreateTemp("", "vault-import-*.zip")
	if err != nil {
		return apperr.NewInternal("failed to create temp file", err)
	}
	defer os.Remove(tmpZip.Name())

	if _, err := io.Copy(tmpZip, file); err != nil {
		return apperr.NewInternal("failed to save backup file", err)
	}
	tmpZip.Close()

	zr, err := zip.OpenReader(tmpZip.Name())
	if err != nil {
		return apperr.NewBadRequest("invalid ZIP file")
	}
	defer zr.Close()

	hasManifest := false
	hasDB := false
	tmpExtractDir, err := os.MkdirTemp("", "vault-extract-*")
	if err != nil {
		return apperr.NewInternal("failed to create temp directory", err)
	}
	defer os.RemoveAll(tmpExtractDir)

	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			hasManifest = true
		}
		if f.Name == "vault.db" {
			hasDB = true
		}

		if err := h.extractZipFile(f, tmpExtractDir); err != nil {
			return apperr.NewBadRequest("failed to extract backup")
		}
	}

	if !hasManifest || !hasDB {
		return apperr.NewBadRequest("invalid backup: missing manifest or database")
	}

	if err := h.db.ForceCheckpoint(); err != nil {
		return apperr.NewInternal("failed to prepare current database", err)
	}

	h.db.Close()

	dbPath := h.db.GetPath()
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

	if err := h.db.Reconnect(); err != nil {
		return apperr.NewInternal("failed to reconnect database", err)
	}

	// Invalidate sessions so existing JWTs no longer work
	if err := h.db.Queries.InvalidateSessions(ctx); err != nil {
		return apperr.NewInternal("failed to invalidate sessions", err)
	}

	// Return success - frontend will handle redirect and token clearing
	return httputil.OKResult(w, map[string]string{"status": "success"})
}

// extractZipFile extracts a single file from ZIP
func (h *InstanceHandler) extractZipFile(f *zip.File, dest string) error {
	path := filepath.Join(dest, f.Name)

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

// ResetInstance deletes all data and restores to clean state
func (h *InstanceHandler) ResetInstance(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	user, err := h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil || !user.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	type NewAdminRequest struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	type ResetRequest struct {
		ConfirmName string           `json:"confirm_name"`
		NewAdmin    *NewAdminRequest `json:"new_admin,omitempty"`
	}
	var req ResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request")
	}

	instanceInfo, err := h.db.Queries.GetInstanceSettings(ctx)
	if err != nil {
		return apperr.NewInternal("failed to get instance info", err)
	}

	if req.ConfirmName != instanceInfo.Name {
		return apperr.NewBadRequest("instance name does not match")
	}

	h.db.Close()

	dbPath := h.db.GetPath()
	os.Remove(dbPath)
	os.Remove(dbPath + "-shm")
	os.Remove(dbPath + "-wal")

	projectsDir := filepath.Join(h.dataDir, "projects")
	os.RemoveAll(projectsDir)
	os.MkdirAll(projectsDir, 0755)

	if err := h.db.Reconnect(); err != nil {
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

		if _, err := h.db.Queries.CreateUser(ctx, sqlc.CreateUserParams{
			Username:     req.NewAdmin.Username,
			Email:        req.NewAdmin.Email,
			PasswordHash: passwordHash,
			IsAdmin:      true,
			IsOwner:      true,
		}); err != nil {
			return apperr.NewInternal("failed to create admin user", err)
		}
	}

	if err := h.db.Queries.InvalidateSessions(ctx); err != nil {
		return apperr.NewInternal("failed to invalidate sessions", err)
	}

	return httputil.OKResult(w, map[string]string{"status": "success"})
}
