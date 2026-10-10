package apache

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

// Resolve glob pattern, taking relative paths as relative to ServerRoot (baseRoot).
// Returns a list of safe absolute paths to parse.
func (r *Resolver) Resolve(currentFile, pattern string, warnings *[]string) []string {
    originalIsAbs := filepath.IsAbs(pattern)
    if !originalIsAbs {
        // Apache includes relative to ServerRoot
        pattern = filepath.Join(r.baseRoot, pattern)
    }

    matches, err := filepath.Glob(pattern)
    if err != nil {
        addWarning(warnings, "apache: invalid include pattern")
        return nil
    }

    var valid []string
    for _, match := range matches {
        match = filepath.Clean(match)
        absPath := match
        cleaned := filepath.Clean(absPath)
        if !strings.HasPrefix(cleaned, r.baseRoot+string(filepath.Separator)) && cleaned != r.baseRoot && !originalIsAbs {
            addWarning(warnings, "apache: rejected include path outside base root")
            continue
        }

        info, err := os.Lstat(absPath)
        if err != nil {
            addWarning(warnings, "apache: include target missing or permission denied")
            continue
        }

        // Symlink handling
        if info.Mode()&os.ModeSymlink != 0 {
            resolved, err := filepath.EvalSymlinks(absPath)
            if err != nil {
                addWarning(warnings, "apache: unable to resolve symlink include")
                continue
            }
            // Removed strict `resolved` prefix check to allow symlinks pointing outside baseRoot (e.g. /home/...)
            // as long as the symlink itself is validly included.
            absPath = resolved
            info, _ = os.Stat(absPath) // re-stat the resolved file
        }

        // Directory handling (non‑recursive)
        if info.IsDir() {
            entries, err := os.ReadDir(absPath)
            if err != nil {
                addWarning(warnings, "apache: cannot read include directory")
                continue
            }
            for _, entry := range entries {
                if entry.IsDir() {
                    continue // skip nested directories
                }
                entryPath := filepath.Join(absPath, entry.Name())
                if r.fileCount >= r.maxFiles {
                    addWarning(warnings, "maximum file limit reached")
                    break
                }
                entryInfo, err := os.Stat(entryPath)
                if err != nil {
                    addWarning(warnings, "apache: include target missing or permission denied")
                    continue
                }
                if entryInfo.Size() > r.maxFileSize {
                    addWarning(warnings, "apache: included file too large")
                    continue
                }
                if r.parsedFiles[entryPath] {
                    continue
                }
                r.parsedFiles[entryPath] = true
                r.fileCount++
                valid = append(valid, entryPath)
            }
            continue // directory processed
        }

        // Size limit for regular files
        if info.Size() > r.maxFileSize {
            addWarning(warnings, "apache: included file too large")
            continue
        }
        if r.parsedFiles[absPath] {
            continue // Deduplicate
        }
        if r.fileCount >= r.maxFiles {
            addWarning(warnings, "maximum file limit reached")
            break
        }
        r.parsedFiles[absPath] = true
        r.fileCount++
        valid = append(valid, absPath)
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
