package transcoding

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var AllowedAudioExtensions = map[string]bool{
	".wav":  true,
	".flac": true,
	".mp3":  true,
	".aac":  true,
	".ogg":  true,
	".aiff": true,
	".aif":  true,
	".alac": true,
	".m4a":  true,
	".wma":  true,
	".opus": true,
	".webm": true,
}

var VideoExtensions = map[string]bool{
	".mp4": true,
	".mov": true,
	".mkv": true,
	".avi": true,
	".webm": true,
}

// IsAllowedUploadExtension returns true if the extension is an allowed audio or video format.
func IsAllowedUploadExtension(ext string) bool {
	ext = strings.ToLower(ext)
	return AllowedAudioExtensions[ext] || VideoExtensions[ext]
}

// IsVideoExtension returns true if the extension is a video format.
func IsVideoExtension(ext string) bool {
	ext = strings.ToLower(ext)
	return VideoExtensions[ext]
}

// ExtractAudioToWAV extracts audio from a video file to WAV format using ffmpeg.
// It returns the path to the new WAV file and deletes the original video file.
func ExtractAudioToWAV(inputPath string) (string, error) {
	ext := filepath.Ext(inputPath)
	outputPath := strings.TrimSuffix(inputPath, ext) + ".wav"

	cmd := exec.Command("ffmpeg",
		"-i", inputPath,
		"-vn",
		"-acodec", "pcm_s24le",
		"-y",
		outputPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("ffmpeg failed: %w: %s", err, string(output))
	}

	if err := os.Remove(inputPath); err != nil {
		return outputPath, fmt.Errorf("failed to remove original video file: %w", err)
	}

	return outputPath, nil
}
