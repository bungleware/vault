package httputil

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func OK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, data)
}

func Created(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusCreated, data)
}

func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func OKResult(w http.ResponseWriter, data any) error {
	OK(w, data)
	return nil
}

func CreatedResult(w http.ResponseWriter, data any) error {
	Created(w, data)
	return nil
}

func NoContentResult(w http.ResponseWriter) error {
	NoContent(w)
	return nil
}
