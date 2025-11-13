package middleware

import (
	"deskrow/rate"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func RateLimit(limiter *rate.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)
			username := getUsername(r)

			// Track and check IP limits
			if _, err := limiter.Increment("ip:" + ip); err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if blocked, _ := limiter.IsBlocked("ip:" + ip); blocked {
				respondRateLimited(w, limiter.Config.IPBanDuration)
				return
			}

			// Track and check username limits if available
			if username != "" {
				if _, err := limiter.Increment("user:" + username); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				if blocked, _ := limiter.IsBlocked("user:" + username); blocked {
					respondRateLimited(w, limiter.Config.UsernameBanDuration)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getIP(r *http.Request) string {
	// Get IP from X-Forwarded-For header if behind proxy
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func getUsername(r *http.Request) string {
	// Extract username from JWT token in Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Expecting "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	// In a real implementation, you would decode the JWT here
	// and extract the username from the claims
	// This is a simplified placeholder
	return "user123" // Replace with actual JWT parsing
}

func respondRateLimited(w http.ResponseWriter, duration time.Duration) {
	retryAfter := int(duration.Seconds())
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte("Too many requests, please try again later"))
}
