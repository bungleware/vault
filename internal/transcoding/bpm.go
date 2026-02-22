package transcoding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"
)

type BPMRequest struct {
	FilePath string `json:"file_path"`
}

type BPMResponse struct {
	BPM      int    `json:"bpm"`
	FilePath string `json:"file_path"`
}

type KeyResponse struct {
	Key       string `json:"key"`
	Scale     string `json:"scale"`
	KeyString string `json:"key_string"`
	FilePath  string `json:"file_path"`
}

type AnalysisResponse struct {
	BPM       int    `json:"bpm"`
	Key       string `json:"key"`
	Scale     string `json:"scale"`
	KeyString string `json:"key_string"`
	FilePath  string `json:"file_path"`
}

type ErrorResponse struct {
	Detail string `json:"detail"`
}

const (
	BPMServiceURL     = "http://127.0.0.1:8001"
	BPMServiceTimeout = 30 * time.Second
)

func callAudioService[T any](endpoint string, filePath string, serviceName string) (T, error) {
	var result T

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return result, fmt.Errorf("failed to get absolute path: %w", err)
	}

	reqBody := BPMRequest{
		FilePath: absFilePath,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return result, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{
		Timeout: BPMServiceTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), BPMServiceTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		BPMServiceURL+endpoint,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return result, fmt.Errorf("%s timed out after %v", serviceName, BPMServiceTimeout)
		}
		return result, fmt.Errorf("failed to connect to audio service: %w (is the service running?)", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return result, fmt.Errorf("audio service error (status %d): %s", resp.StatusCode, errResp.Detail)
		}
		return result, fmt.Errorf("audio service error (status %d): %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

func DetectBPM(filePath string) (int, error) {
	result, err := callAudioService[BPMResponse]("/detect-bpm", filePath, "BPM detection")
	if err != nil {
		return 0, err
	}

	if result.BPM < 20 || result.BPM > 300 {
		return 0, fmt.Errorf("detected BPM %d is outside valid range (20-300)", result.BPM)
	}

	return result.BPM, nil
}

func DetectKey(filePath string) (string, error) {
	result, err := callAudioService[KeyResponse]("/detect-key", filePath, "key detection")
	if err != nil {
		return "", err
	}

	return result.KeyString, nil
}

func AnalyzeAudio(filePath string) (bpm int, key string, err error) {
	result, err := callAudioService[AnalysisResponse]("/analyze", filePath, "audio analysis")
	if err != nil {
		return 0, "", err
	}

	if result.BPM < 20 || result.BPM > 300 {
		return 0, "", fmt.Errorf("detected BPM %d is outside valid range (20-300)", result.BPM)
	}

	return result.BPM, result.KeyString, nil
}
