// Package sanitizer is a lightweight library that facilitates the safearchive libraries to
// prevent path traversal attempts by sanitize file paths.
package sanitizer

import (
	"os"
)

const (
	winPathSeparator = `\`
	nixPathSeparator = `/`
)

// SanitizePath sanitizes the supplied path by purely lexical processing.
// The return value is safe to be joined together with a base directory (if the basedir is empty
// and no symlinks are present there).
// Join(base, SanitizePath(path)) will always produce a path contained within base and Clean(path)
// will always produce an unrooted path with no ".." path elements.
// If the input path had a directory separator at the end, the sanitized version will preserve that.
func SanitizePath(in string) string {
	sanitized := sanitizePath(in)

	// Add back trailing / if safe
	if len(in) > 0 &&
		(in[len(in)-1] == nixPathSeparator[0] || in[len(in)-1] == winPathSeparator[0]) &&
		len(sanitized) > 0 {
		sanitized = sanitized + string(os.PathSeparator)
	}

	return sanitized
}
