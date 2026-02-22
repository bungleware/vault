package ids

import (
	"crypto/rand"
	"math/big"
)

const (
	publicIDAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	publicIDLength   = 21
)

func NewPublicID() (string, error) {
	result := make([]byte, publicIDLength)
	max := big.NewInt(int64(len(publicIDAlphabet)))

	for i := 0; i < publicIDLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = publicIDAlphabet[n.Int64()]
	}

	return string(result), nil
}
