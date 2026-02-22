package storage

import (
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/chai2010/webp"
	"github.com/disintegration/imaging"
)

type FilesystemStorage struct {
	baseDir string
}

func NewFilesystemStorage(baseDir string) *FilesystemStorage {
	return &FilesystemStorage{baseDir: baseDir}
}

func (s *FilesystemStorage) SaveTrackSource(ctx context.Context, input SaveTrackSourceInput) (*SaveTrackSourceResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	versionDir := s.versionDir(input.ProjectPublicID, input.TrackID, input.VersionID)
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create version directory: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(input.OriginalName))
	if ext == "" {
		ext = ".bin"
	}

	filePath := filepath.Join(versionDir, "source"+ext)
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create source file: %w", err)
	}
	defer file.Close()

	size, err := io.Copy(file, input.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to write source file: %w", err)
	}

	format := strings.TrimPrefix(ext, ".")
	if format == "" {
		format = "bin"
	}

	return &SaveTrackSourceResult{
		Path:   filePath,
		Size:   size,
		Format: format,
	}, nil
}

func (s *FilesystemStorage) DeleteTrack(ctx context.Context, input DeleteTrackInput) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	trackDir := s.trackDir(input.ProjectPublicID, input.TrackID)
	if err := os.RemoveAll(trackDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete track directory: %w", err)
	}

	return nil
}

func (s *FilesystemStorage) DeleteVersion(ctx context.Context, input DeleteVersionInput) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	versionDir := s.versionDir(input.ProjectPublicID, input.TrackID, input.VersionID)
	if err := os.RemoveAll(versionDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete version directory: %w", err)
	}

	return nil
}

func (s *FilesystemStorage) trackDir(projectPublicID string, trackID int64) string {
	return filepath.Join(s.projectDir(projectPublicID), "tracks", fmt.Sprintf("%d", trackID))
}

func (s *FilesystemStorage) versionDir(projectPublicID string, trackID, versionID int64) string {
	return filepath.Join(s.trackDir(projectPublicID, trackID), "versions", fmt.Sprintf("%d", versionID))
}

func (s *FilesystemStorage) projectDir(projectPublicID string) string {
	return filepath.Join(s.baseDir, "projects", projectPublicID)
}

func (s *FilesystemStorage) coverDir(projectPublicID string) string {
	return filepath.Join(s.projectDir(projectPublicID), "cover")
}

func (s *FilesystemStorage) SaveProjectCover(ctx context.Context, input SaveProjectCoverInput) (*SaveProjectCoverResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	dir := s.coverDir(input.ProjectPublicID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to clean existing cover: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create cover directory: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(input.OriginalName))
	if ext == "" {
		ext = ".img"
	}

	path := filepath.Join(dir, "cover"+ext)

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create cover file: %w", err)
	}
	defer file.Close()

	size, err := io.Copy(file, input.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to write cover file: %w", err)
	}

	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return &SaveProjectCoverResult{
		Path: absPath,
		Mime: mimeType,
		Size: size,
	}, nil
}

func (s *FilesystemStorage) SaveProcessedCover(ctx context.Context, input SaveProcessedCoverInput) (*SaveProcessedCoverResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	dir := s.coverDir(input.ProjectPublicID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to clean existing cover: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create cover directory: %w", err)
	}

	ext := strings.ToLower(input.SourceExt)
	if ext == "" {
		ext = ".img"
	}
	sourcePath := filepath.Join(dir, "source"+ext)
	if err := os.WriteFile(sourcePath, input.Source, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write source cover: %w", err)
	}

	smallPath := filepath.Join(dir, "small.webp")
	if err := os.WriteFile(smallPath, input.Small, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write small cover: %w", err)
	}

	mediumPath := filepath.Join(dir, "medium.webp")
	if err := os.WriteFile(mediumPath, input.Medium, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write medium cover: %w", err)
	}

	largePath := filepath.Join(dir, "large.webp")
	if err := os.WriteFile(largePath, input.Large, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write large cover: %w", err)
	}

	absSourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	return &SaveProcessedCoverResult{
		SourcePath: absSourcePath,
		SourceMime: mimeType,
	}, nil
}

func (s *FilesystemStorage) DeleteProjectCover(ctx context.Context, input DeleteProjectCoverInput) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	dir := s.coverDir(input.ProjectPublicID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete cover directory: %w", err)
	}
	return nil
}

var coverSizeDimensions = map[string]int{
	"small":  256,
	"medium": 512,
	"large":  1024,
}

func (s *FilesystemStorage) OpenProjectCover(ctx context.Context, input OpenProjectCoverInput) (*ProjectCoverStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	wantSized := input.Size != "" && input.Size != "source"

	if wantSized {
		coverDir := s.coverDir(input.ProjectPublicID)
		sizedPath := filepath.Join(coverDir, input.Size+".webp")
		if _, err := os.Stat(sizedPath); err == nil {
			return s.openFile(sizedPath)
		}
	}

	sourcePath := s.resolveSourcePath(input)
	if sourcePath == "" {
		return nil, fmt.Errorf("no cover file found for project %s", input.ProjectPublicID)
	}

	if !wantSized {
		return s.openFile(sourcePath)
	}

	dim, ok := coverSizeDimensions[input.Size]
	if !ok {
		return s.openFile(sourcePath)
	}

	resized, err := s.resizeAndCache(sourcePath, input.ProjectPublicID, input.Size, dim)
	if err != nil {
		slog.Warn("on-the-fly cover resize failed, serving source", "project", input.ProjectPublicID, "size", input.Size, "error", err)
		return s.openFile(sourcePath)
	}

	return &ProjectCoverStream{
		Reader: io.NopCloser(bytes.NewReader(resized)),
		Size:   int64(len(resized)),
	}, nil
}

func (s *FilesystemStorage) resolveSourcePath(input OpenProjectCoverInput) string {
	coverDir := s.coverDir(input.ProjectPublicID)
	entries, err := os.ReadDir(coverDir)
	if err == nil {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "source.") {
				return filepath.Join(coverDir, entry.Name())
			}
		}
	}

	path := input.Path
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		baseDirName := filepath.Base(s.baseDir)
		if !strings.HasPrefix(path, baseDirName+string(filepath.Separator)) &&
			!strings.HasPrefix(path, filepath.Clean(s.baseDir)) {
			path = filepath.Join(s.baseDir, path)
		}
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func (s *FilesystemStorage) openFile(path string) (*ProjectCoverStream, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open cover file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat cover file: %w", err)
	}
	return &ProjectCoverStream{
		Reader: file,
		Size:   info.Size(),
	}, nil
}

func (s *FilesystemStorage) resizeAndCache(sourcePath, projectPublicID, sizeName string, dim int) ([]byte, error) {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source: %w", err)
	}
	defer sourceFile.Close()

	img, _, err := image.Decode(sourceFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	quality := float32(85)
	if sizeName == "large" {
		quality = 90
	}

	resized := imaging.Fill(img, dim, dim, imaging.Center, imaging.Lanczos)

	var buf bytes.Buffer
	if err := webp.Encode(&buf, resized, &webp.Options{Lossless: false, Quality: quality}); err != nil {
		return nil, fmt.Errorf("failed to encode webp: %w", err)
	}

	coverDir := s.coverDir(projectPublicID)
	if err := os.MkdirAll(coverDir, 0o755); err == nil {
		cachedPath := filepath.Join(coverDir, sizeName+".webp")
		if writeErr := os.WriteFile(cachedPath, buf.Bytes(), 0o644); writeErr != nil {
			slog.Warn("failed to cache resized cover", "path", cachedPath, "error", writeErr)
		}
	}

	return buf.Bytes(), nil
}

func (s *FilesystemStorage) DeleteProject(ctx context.Context, input DeleteProjectInput) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	dir := s.projectDir(input.ProjectPublicID)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete project directory: %w", err)
	}
	return nil
}
