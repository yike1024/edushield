package main

import (
	"os"
	"strings"
)

// envOr returns the trimmed environment variable value or def when unset/blank.
// Defined as a shared helper so adapters don't reach into os.Getenv directly.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return def
}

// getenv returns the raw env value (no trim); some callers want empty string
// for "set but blank" (e.g. NVD API key explicitly cleared).
func getenv(key string) string { return os.Getenv(key) }
