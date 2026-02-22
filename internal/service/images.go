package service

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"

	"github.com/chai2010/webp"
	"github.com/disintegration/imaging"
)

type CoverSize string

const (
	CoverSizeSmall  CoverSize = "small"  // 256x256
	CoverSizeMedium CoverSize = "medium" // 512x512
	CoverSizeLarge  CoverSize = "large"  // 1024x1024
	CoverSizeSource CoverSize = "source" // Original
)

var CoverSizes = map[CoverSize]int{
	CoverSizeSmall:  256,
	CoverSizeMedium: 512,
	CoverSizeLarge:  1024,
}

type ProcessedCover struct {
	Small  []byte // 256x256 WebP
	Medium []byte // 512x512 WebP
	Large  []byte // 1024x1024 WebP
	Source []byte // Original file data
}

func ProcessCoverImage(reader io.Reader) (*ProcessedCover, error) {
	sourceData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read image data: %w", err)
	}
	img, _, err := image.Decode(bytes.NewReader(sourceData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	result := &ProcessedCover{
		Source: sourceData,
	}

	smallImg := imaging.Fill(img, CoverSizes[CoverSizeSmall], CoverSizes[CoverSizeSmall], imaging.Center, imaging.Lanczos)
	result.Small, err = encodeWebP(smallImg, 85)
	if err != nil {
		return nil, fmt.Errorf("failed to encode small cover: %w", err)
	}

	mediumImg := imaging.Fill(img, CoverSizes[CoverSizeMedium], CoverSizes[CoverSizeMedium], imaging.Center, imaging.Lanczos)
	result.Medium, err = encodeWebP(mediumImg, 85)
	if err != nil {
		return nil, fmt.Errorf("failed to encode medium cover: %w", err)
	}

	largeImg := imaging.Fill(img, CoverSizes[CoverSizeLarge], CoverSizes[CoverSizeLarge], imaging.Center, imaging.Lanczos)
	result.Large, err = encodeWebP(largeImg, 90)
	if err != nil {
		return nil, fmt.Errorf("failed to encode large cover: %w", err)
	}

	return result, nil
}

func encodeWebP(img image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	err := webp.Encode(&buf, img, &webp.Options{
		Lossless: false,
		Quality:  float32(quality),
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ValidCoverSize(size string) bool {
	switch CoverSize(size) {
	case CoverSizeSmall, CoverSizeMedium, CoverSizeLarge, CoverSizeSource:
		return true
	default:
		return false
	}
}
