package httputil

import (
	"database/sql"
	"time"
)

func NullStringToPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func NullInt64ToPtr(ni sql.NullInt64) *int64 {
	if ni.Valid {
		return &ni.Int64
	}
	return nil
}

func NullFloat64ToPtr(nf sql.NullFloat64) *float64 {
	if nf.Valid {
		return &nf.Float64
	}
	return nil
}

func FormatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05Z07:00")
}

func FormatNullTime(t sql.NullTime) *string {
	if !t.Valid {
		return nil
	}
	str := t.Time.Format("2006-01-02T15:04:05Z07:00")
	return &str
}

func FormatNullTimeString(t sql.NullTime) string {
	if !t.Valid {
		return ""
	}
	return t.Time.Format("2006-01-02T15:04:05Z07:00")
}
