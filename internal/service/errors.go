package service

import "errors"

// Common service-layer sentinel errors. Handlers map these to HTTP status codes.
var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrBadRequest = errors.New("bad request")
	ErrConflict   = errors.New("conflict")

	// Share validation sentinel errors — handlers map these to {valid: false, ...} responses.
	ErrPasswordRequired   = errors.New("password required")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrShareExpired       = errors.New("share expired")
	ErrAccessLimitReached = errors.New("access limit reached")
	ErrDownloadNotAllowed = errors.New("download not allowed")
)
