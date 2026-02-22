package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrForbidden     = errors.New("forbidden")
	ErrBadRequest    = errors.New("bad request")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrConflict      = errors.New("conflict")
	ErrInternal      = errors.New("internal error")
	ErrInvalidInput  = errors.New("invalid input")
	ErrAlreadyExists = errors.New("already exists")
)

type AppError struct {
	Err     error
	Message string
	Status  int
}

func (e *AppError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Err.Error()
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func New(status int, err error, message string) *AppError {
	return &AppError{
		Err:     err,
		Message: message,
		Status:  status,
	}
}

func NewBadRequest(message string) *AppError {
	return &AppError{
		Err:     ErrBadRequest,
		Message: message,
		Status:  http.StatusBadRequest,
	}
}

func NewUnauthorized(message string) *AppError {
	return &AppError{
		Err:     ErrUnauthorized,
		Message: message,
		Status:  http.StatusUnauthorized,
	}
}

func NewForbidden(message string) *AppError {
	return &AppError{
		Err:     ErrForbidden,
		Message: message,
		Status:  http.StatusForbidden,
	}
}

func NewNotFound(message string) *AppError {
	return &AppError{
		Err:     ErrNotFound,
		Message: message,
		Status:  http.StatusNotFound,
	}
}

func NewConflict(message string) *AppError {
	return &AppError{
		Err:     ErrConflict,
		Message: message,
		Status:  http.StatusConflict,
	}
}

func NewInternal(message string, err error) *AppError {
	return &AppError{
		Err:     err,
		Message: message,
		Status:  http.StatusInternalServerError,
	}
}

func Wrap(err error, message string) error {
	return fmt.Errorf("%s: %w", message, err)
}
