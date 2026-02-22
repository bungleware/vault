package storage

import (
	"context"
	"io"
)

type Storage interface {
	SaveTrackSource(ctx context.Context, input SaveTrackSourceInput) (*SaveTrackSourceResult, error)
	DeleteTrack(ctx context.Context, input DeleteTrackInput) error
	DeleteVersion(ctx context.Context, input DeleteVersionInput) error
	DeleteProject(ctx context.Context, input DeleteProjectInput) error

	SaveProjectCover(ctx context.Context, input SaveProjectCoverInput) (*SaveProjectCoverResult, error)
	SaveProcessedCover(ctx context.Context, input SaveProcessedCoverInput) (*SaveProcessedCoverResult, error)
	DeleteProjectCover(ctx context.Context, input DeleteProjectCoverInput) error
	OpenProjectCover(ctx context.Context, input OpenProjectCoverInput) (*ProjectCoverStream, error)
}

type SaveTrackSourceInput struct {
	ProjectPublicID string
	TrackID         int64
	VersionID       int64
	OriginalName    string
	Reader          io.Reader
}

type SaveTrackSourceResult struct {
	Path   string
	Size   int64
	Format string
}

type DeleteTrackInput struct {
	ProjectPublicID string
	TrackID         int64
}

type DeleteVersionInput struct {
	ProjectPublicID string
	TrackID         int64
	VersionID       int64
}

type DeleteProjectInput struct {
	ProjectPublicID string
}

type SaveProjectCoverInput struct {
	ProjectPublicID string
	OriginalName    string
	Reader          io.Reader
}

type SaveProjectCoverResult struct {
	Path string
	Mime string
	Size int64
}

type DeleteProjectCoverInput struct {
	ProjectPublicID string
}

type OpenProjectCoverInput struct {
	ProjectPublicID string
	Path            string
	Size            string
}

type ProjectCoverStream struct {
	Reader io.ReadCloser
	Size   int64
}

type SaveProcessedCoverInput struct {
	ProjectPublicID string
	SourceExt       string // Original file extension (e.g., ".jpg", ".png")
	Source          []byte // Original file data
	Small           []byte // 256x256 WebP
	Medium          []byte // 512x512 WebP
	Large           []byte // 1024x1024 WebP
}

type SaveProcessedCoverResult struct {
	SourcePath string
	SourceMime string
}
