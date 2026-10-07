package collector

import (
	"net/url"
	"regexp"
	"strings"
)

const maxRedactedCommandLineLen = 512

var jwtLikePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func redactCommandLine(args []string) string {
	if len(args) == 0 {
		return ""
	}

	redacted := make([]string, 0, len(args))
	redactNext := false

	for _, arg := range args {
		if redactNext {
			redacted = append(redacted, "REDACTED")
			redactNext = false
			continue
		}

		if strings.EqualFold(arg, "bearer") || looksLikeJWT(arg) {
			redacted = append(redacted, "REDACTED")
			if strings.EqualFold(arg, "bearer") {
				redactNext = true
			}
			continue
		}

		key, value, hasValue := splitArg(arg)
		if isSensitiveKey(key) {
			if hasValue {
				prefix := arg[:strings.Index(arg, "=")]
				redacted = append(redacted, prefix+"=REDACTED")
			} else {
				redacted = append(redacted, arg)
				redactNext = true
			}
			continue
		}

		if u := redactURL(arg); u != arg {
			redacted = append(redacted, u)
			continue
		}

		if hasValue {
			prefix := arg[:strings.Index(arg, "=")]
			redacted = append(redacted, prefix+"="+redactURL(value))
			continue
		}

		redacted = append(redacted, redactURL(arg))
	}

	line := strings.Join(redacted, " ")
	if len(line) > maxRedactedCommandLineLen {
		return line[:maxRedactedCommandLineLen]
	}
	return line
}

func splitArg(arg string) (key, value string, hasValue bool) {
	if idx := strings.Index(arg, "="); idx >= 0 {
		return strings.ToLower(strings.TrimLeft(arg[:idx], "-")), arg[idx+1:], true
	}
	return strings.ToLower(strings.TrimLeft(arg, "-")), "", false
}

func isSensitiveKey(key string) bool {
	key = strings.ReplaceAll(strings.ToLower(key), "-", "_")
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}

	exact := map[string]bool{
		"password":     true,
		"passwd":       true,
		"pwd":          true,
		"token":        true,
		"secret":       true,
		"key":          true,
		"api_key":      true,
		"apikey":       true,
		"private_key":  true,
		"credential":   true,
		"credentials":  true,
		"database_url": true,
		"db_url":       true,
		"dsn":          true,
		"auth":         true,
		"bearer":       true,
		"jwt":          true,
	}
	if exact[key] {
		return true
	}

	suffixes := []string{
		"_password",
		"_passwd",
		"_pwd",
		"_token",
		"_secret",
		"_key",
		"_credential",
		"_credentials",
		"_database_url",
		"_db_url",
		"_dsn",
		"_auth",
		"_bearer",
		"_jwt",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}

	return strings.Contains(key, "api_key")
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
		return raw
	}

	if u.User != nil {
		u.User = url.User("REDACTED")
	}

	query := u.Query()
	changed := false
	for key := range query {
		if isSensitiveKey(key) {
			query.Set(key, "REDACTED")
			changed = true
		}
	}
	if changed {
		u.RawQuery = query.Encode()
	}

	return u.String()
}

func looksLikeJWT(value string) bool {
	return jwtLikePattern.MatchString(value)
}
