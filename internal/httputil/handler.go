package httputil

import (
	"errors"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
)

// AppHandler is an HTTP handler that returns an error.
// If non-nil, the error is translated to an HTTP response by Wrap.
// Wrap converts an AppHandler into a standard http.HandlerFunc.

type AppHandler func(w http.ResponseWriter, r *http.Request) error

func Wrap(h AppHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			var appErr *apperr.AppError
			if errors.As(err, &appErr) {
				http.Error(w, appErr.Message, appErr.Status)
			} else {
				slog.ErrorContext(r.Context(), "unhandled error", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}
	}
}
