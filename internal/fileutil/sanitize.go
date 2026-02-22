package fileutil

import (
	"regexp"
	"strings"
)

type SanitizeOptions struct {
	Replacement string
	MaxLength   int
}

func DefaultSanitizeOptions() SanitizeOptions {
	return SanitizeOptions{
		Replacement: "_",
		MaxLength:   50,
	}
}

var invalidFilenameCharsRegex = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

func SanitizeFilename(name string, opts ...SanitizeOptions) string {
	options := DefaultSanitizeOptions()
	if len(opts) > 0 {
		options = opts[0]
	}

	sanitized := invalidFilenameCharsRegex.ReplaceAllString(name, options.Replacement)

	sanitized = strings.ReplaceAll(sanitized, " ", options.Replacement)

	sanitized = strings.Trim(sanitized, ". ")

	if sanitized == "" {
		sanitized = "untitled"
	}

	if options.MaxLength > 0 && len(sanitized) > options.MaxLength {
		sanitized = sanitized[:options.MaxLength]
	}

	return sanitized
}
