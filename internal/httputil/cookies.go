package httputil

import (
	"net/http"
	"strings"
	"time"

	"bungleware/vault/internal/auth"
)

func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken, csrfToken string, config auth.Config) {
	accessCookie := buildCookie(auth.AccessTokenCookieName, accessToken, config, config.JWTExpiration, true)
	refreshCookie := buildCookie(auth.RefreshTokenCookieName, refreshToken, config, config.RefreshExpiration, true)
	csrfCookie := buildCookie(auth.CSRFCookieName, csrfToken, config, config.RefreshExpiration, false)

	http.SetCookie(w, accessCookie)
	http.SetCookie(w, refreshCookie)
	http.SetCookie(w, csrfCookie)
}

func ClearAuthCookies(w http.ResponseWriter, config auth.Config) {
	clearCookie := func(name string, httpOnly bool) {
		cookie := buildCookie(name, "", config, -1*time.Hour, httpOnly)
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	clearCookie(auth.AccessTokenCookieName, true)
	clearCookie(auth.RefreshTokenCookieName, true)
	clearCookie(auth.CSRFCookieName, false)
}

func buildCookie(name, value string, config auth.Config, ttl time.Duration, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   config.CookieDomain,
		HttpOnly: httpOnly,
		Secure:   config.CookieSecure,
		SameSite: parseSameSite(config.CookieSameSite),
		Expires:  time.Now().Add(ttl),
	}
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
