package httputil

import (
	"database/sql"
	"errors"

	"bungleware/vault/internal/apperr"
)

// HandleDBError maps common database errors to AppErrors.
// sql.ErrNoRows becomes a 404 with notFoundMsg; other errors become 500s with internalMsg.
func HandleDBError(err error, notFoundMsg, internalMsg string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.NewNotFound(notFoundMsg)
	}
	return apperr.NewInternal(internalMsg, err)
}
