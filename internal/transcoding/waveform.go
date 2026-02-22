package transcoding

import (
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
)

func GenerateWaveform(inputPath string, numBars int) ([]int, error) {
	if numBars <= 0 {
		numBars = 200
	}

	metadata, err := ExtractMetadata(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract metadata: %w", err)
	}

	if metadata.Duration <= 0 {
		return nil, fmt.Errorf("invalid duration: %f", metadata.Duration)
	}

	samplesPerBar := int(math.Ceil(metadata.Duration * float64(metadata.SampleRate) / float64(numBars)))

	cmd := exec.Command(
		"ffmpeg",
		"-i", inputPath,
		"-af", fmt.Sprintf("aresample=8000,asetnsamples=%d,astats=metadata=1:reset=1", samplesPerBar),
		"-f", "null",
		"-",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return generateWaveformFromPCM(inputPath, numBars)
	}

	_ = output
	return generateWaveformFromPCM(inputPath, numBars)
}

func generateWaveformFromPCM(inputPath string, numBars int) ([]int, error) {
	cmd := exec.Command(
		"ffmpeg",
		"-i", inputPath,
		"-ac", "1",
		"-ar", "8000",
		"-f", "s16le",
		"-",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to extract PCM data: %w", err)
	}

	numSamples := len(output) / 2
	samples := make([]int16, numSamples)
	for i := 0; i < numSamples; i++ {
		samples[i] = int16(output[i*2]) | int16(output[i*2+1])<<8
	}

	samplesPerBar := numSamples / numBars
	if samplesPerBar < 1 {
		samplesPerBar = 1
	}

	waveform := make([]int, numBars)
	maxRMS := 0.0

	rmsValues := make([]float64, numBars)
	for i := 0; i < numBars; i++ {
		start := i * samplesPerBar
		end := start + samplesPerBar
		if end > numSamples {
			end = numSamples
		}

		sum := 0.0
		count := 0
		for j := start; j < end; j++ {
			val := float64(samples[j])
			sum += val * val
			count++
		}

		if count > 0 {
			rms := math.Sqrt(sum / float64(count))
			rmsValues[i] = rms
			if rms > maxRMS {
				maxRMS = rms
			}
		}
	}

	// Second pass: normalize to 0-100 range using a fixed reference level
	// This preserves relative loudness between tracks
	// For 16-bit PCM, max value is 32768. We use 70% as reference for typical loud audio
	const referenceLevel = 32768.0 * 0.7

	for i := 0; i < numBars; i++ {
		amplitude := rmsValues[i] / referenceLevel

		if amplitude > 1.0 {
			amplitude = 1.0
		}

		// This gives more visual range to quieter sounds while preserving loudness differences
		logScaled := math.Log10(1 + 9*amplitude) // log10(1) = 0, log10(10) = 1

		height := int(5 + logScaled*75)
		if height < 5 {
			height = 5
		}
		if height > 80 {
			height = 80
		}
		waveform[i] = height
	}

	return waveform, nil
}

func WaveformToJSON(waveform []int) (string, error) {
	data, err := json.Marshal(waveform)
	if err != nil {
		return "", fmt.Errorf("failed to marshal waveform: %w", err)
	}
	return string(data), nil
}

func WaveformFromJSON(jsonStr string) ([]int, error) {
	var waveform []int
	err := json.Unmarshal([]byte(jsonStr), &waveform)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal waveform: %w", err)
	}
	return waveform, nil
}

func GenerateWaveformJSON(inputPath string, numBars int) (string, error) {
	waveform, err := GenerateWaveform(inputPath, numBars)
	if err != nil {
		return "", err
	}
	return WaveformToJSON(waveform)
}

func parseFloatArray(s string) ([]float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")

	if s == "" {
		return []float64{}, nil
	}

	parts := strings.Split(s, ",")
	result := make([]float64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse float: %w", err)
		}
		result = append(result, val)
	}

	return result, nil
}
