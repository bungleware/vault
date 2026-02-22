package sqlutil

import (
	"database/sql"
	"time"
)

// NullInt64 converts a pointer to int64 into a sql.NullInt64.
func NullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

// NullInt64Val wraps an int64 value in a valid sql.NullInt64.
func NullInt64Val(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: true}
}

// NullString converts a pointer to string into a sql.NullString.
func NullString(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

// NullStringVal wraps a string value in a valid sql.NullString.
func NullStringVal(v string) sql.NullString {
	return sql.NullString{String: v, Valid: true}
}

// NullFloat64 converts a pointer to float64 into a sql.NullFloat64.
func NullFloat64(p *float64) sql.NullFloat64 {
	if p == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *p, Valid: true}
}

// NullTime converts a pointer to time.Time into a sql.NullTime.
func NullTime(p *time.Time) sql.NullTime {
	if p == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *p, Valid: true}
}

// StringPtr extracts a pointer from sql.NullString, returning nil if invalid.
func StringPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// Int64Ptr extracts a pointer from sql.NullInt64, returning nil if invalid.
func Int64Ptr(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	return &ni.Int64
}

// Float64Ptr extracts a pointer from sql.NullFloat64, returning nil if invalid.
func Float64Ptr(nf sql.NullFloat64) *float64 {
	if !nf.Valid {
		return nil
	}
	return &nf.Float64
}

// TimePtr extracts a pointer from sql.NullTime, returning nil if invalid.
func TimePtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}
