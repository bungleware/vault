package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type signedURLContextKey string

const signedURLKey signedURLContextKey = "signed_url_valid"

func SignedURLValid(ctx context.Context) bool {
	valid, ok := ctx.Value(signedURLKey).(bool)
	return ok && valid
}

func SignedURLMiddleware(secret string, maxSkew time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}

			if validSignedURL(secret, maxSkew, r.URL) {
				ctx := context.WithValue(r.Context(), signedURLKey, true)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func BuildSignedURL(baseURL, path string, query url.Values, secret string, ttl time.Duration) (string, error) {
	if secret == "" {
		return "", nil
	}

	if query == nil {
		query = url.Values{}
	}

	expiresAt := time.Now().Add(ttl).Unix()
	query.Set("expires", strconv.FormatInt(expiresAt, 10))

	signature := computeSignature(secret, path, query)
	query.Set("signature", signature)

	return baseURL + path + "?" + query.Encode(), nil
}

func validSignedURL(secret string, maxSkew time.Duration, u *url.URL) bool {
	query := u.Query()
	signature := query.Get("signature")
	if signature == "" {
		return false
	}

	expiresStr := query.Get("expires")
	if expiresStr == "" {
		return false
	}
	expiresAt, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now()
	if now.After(time.Unix(expiresAt, 0).Add(maxSkew)) {
		return false
	}

	query.Del("signature")
	computed := computeSignature(secret, u.Path, query)
	return hmac.Equal([]byte(signature), []byte(computed))
}

func computeSignature(secret, path string, query url.Values) string {
	canonical := path
	encoded := query.Encode()
	if encoded != "" {
		canonical = canonical + "?" + encoded
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
