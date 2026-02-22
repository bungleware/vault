package httputil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/middleware"
)

func DecodeJSON[T any](r *http.Request) (T, error) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return v, fmt.Errorf("invalid request body: %w", err)
	}
	return v, nil
}

func PathInt64(r *http.Request, key string) (int64, error) {
	str := r.PathValue(key)
	if str == "" {
		return 0, apperr.NewBadRequest(fmt.Sprintf("missing path parameter: %s", key))
	}

	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, apperr.NewBadRequest(fmt.Sprintf("invalid %s: must be a number", key))
	}

	return val, nil
}

func RequireUserID(r *http.Request) (int, error) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		return 0, fmt.Errorf("user not found in context")
	}
	return userID, nil
}

func RequireUsername(r *http.Request) (string, error) {
	username, ok := middleware.GetUsername(r.Context())
	if !ok {
		return "", fmt.Errorf("username not found in context")
	}
	return username, nil
}
