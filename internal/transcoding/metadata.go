package transcoding

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type AudioMetadata struct {
	Duration   float64
	SampleRate int
	BitDepth   int
	Channels   int
	Bitrate    int
	Format     string
	Codec      string
	IsLossless bool
}

type ffprobeOutput struct {
	Format struct {
		Duration   string `json:"duration"`
		FormatName string `json:"format_name"`
		BitRate    string `json:"bit_rate"`
	} `json:"format"`
	Streams []struct {
		CodecType        string `json:"codec_type"`
		CodecName        string `json:"codec_name"`
		SampleRate       string `json:"sample_rate"`
		Channels         int    `json:"channels"`
		BitsPerSample    int    `json:"bits_per_sample"`
		BitsPerRawSample string `json:"bits_per_raw_sample"`
	} `json:"streams"`
}

func ExtractMetadata(filePath string) (*AudioMetadata, error) {
	cmd := exec.Command(
		"ffprobe",
		"-v", "quiet",
		"-print_format", "json",
		"-show_format",
		"-show_streams",
		filePath,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ffprobe failed: %w", err)
	}

	var probe ffprobeOutput
	if err := json.Unmarshal(output, &probe); err != nil {
		return nil, fmt.Errorf("failed to parse ffprobe output: %w", err)
	}

	metadata := &AudioMetadata{}

	if probe.Format.Duration != "" {
		duration, err := strconv.ParseFloat(probe.Format.Duration, 64)
		if err == nil {
			metadata.Duration = duration
		}
	}

	if probe.Format.FormatName != "" {
		formats := strings.Split(probe.Format.FormatName, ",")
		metadata.Format = formats[0]
	}

	if probe.Format.BitRate != "" {
		bitrate, err := strconv.Atoi(probe.Format.BitRate)
		if err == nil {
			metadata.Bitrate = bitrate
		}
	}

	for _, stream := range probe.Streams {
		if stream.CodecType == "audio" {
			metadata.Codec = stream.CodecName
			metadata.Channels = stream.Channels

			if stream.SampleRate != "" {
				sampleRate, err := strconv.Atoi(stream.SampleRate)
				if err == nil {
					metadata.SampleRate = sampleRate
				}
			}

			if stream.BitsPerSample > 0 {
				metadata.BitDepth = stream.BitsPerSample
			} else if stream.BitsPerRawSample != "" {
				bitDepth, err := strconv.Atoi(stream.BitsPerRawSample)
				if err == nil {
					metadata.BitDepth = bitDepth
				}
			}

			metadata.IsLossless = isLosslessCodec(stream.CodecName)

			break
		}
	}

	return metadata, nil
}

func isLosslessCodec(codec string) bool {
	losslessCodecs := map[string]bool{
		"flac":      true,
		"alac":      true,
		"ape":       true,
		"wavpack":   true,
		"tta":       true,
		"pcm_s16le": true,
		"pcm_s24le": true,
		"pcm_s32le": true,
		"pcm_s16be": true,
		"pcm_s24be": true,
		"pcm_s32be": true,
		"pcm_f32le": true,
		"pcm_f64le": true,
	}
	return losslessCodecs[codec]
}

func FormatSampleRate(hz int) string {
	if hz == 0 {
		return ""
	}
	khz := float64(hz) / 1000.0
	if khz == float64(int(khz)) {
		return fmt.Sprintf("%.0f kHz", khz)
	}
	return fmt.Sprintf("%.1f kHz", khz)
}

func FormatBitDepth(bits int) string {
	if bits == 0 {
		return ""
	}
	return fmt.Sprintf("%d-bit", bits)
}

func FormatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
