package nginx

import (
	"os"
	"path/filepath"
	"strings"
)

type Resolver struct {
	baseRoot    string
	parsedFiles map[string]bool
	fileCount   int
	maxFiles    int
	maxFileSize int64
}

func NewResolver(baseRoot string) *Resolver {
	return &Resolver{
		baseRoot:    filepath.Clean(baseRoot),
		parsedFiles: make(map[string]bool),
		maxFiles:    500,
		maxFileSize: 1024 * 1024, // 1MB
	}
}

// Resolve glob pattern, taking relative paths as relative to currentFile.
// Returns a list of safe absolute paths to parse.
func (r *Resolver) Resolve(currentFile, pattern string, warnings *[]string) []string {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(filepath.Dir(currentFile), pattern)
	}

	matches, err := filepath.Glob(pattern)
	if err != nil {
		addWarning(warnings, "nginx: invalid include pattern")
		return nil
	}

	var valid []string
	for _, match := range matches {
		match = filepath.Clean(match)

		// Enforce containment within baseRoot
		if !strings.HasPrefix(match, r.baseRoot+string(filepath.Separator)) && match != r.baseRoot {
			addWarning(warnings, "nginx: rejected include path outside base root")
			continue
		}

		info, err := os.Stat(match)
		if err != nil {
			addWarning(warnings, "nginx: include target missing or permission denied")
			continue
		}
		if info.IsDir() {
			continue // Glob might match a directory, skip it safely
		}

		if info.Size() > r.maxFileSize {
			addWarning(warnings, "nginx: included file too large")
			continue
		}

		if r.parsedFiles[match] {
			continue // Deduplicate
		}

		if r.fileCount >= r.maxFiles {
			addWarning(warnings, "maximum file limit reached")
			break
		}

		r.parsedFiles[match] = true
		r.fileCount++
		valid = append(valid, match)
	}
	return valid
}

func addWarning(warnings *[]string, warning string) {
	for _, existing := range *warnings {
		if existing == warning {
			return
		}
	}
	*warnings = append(*warnings, warning)
}
