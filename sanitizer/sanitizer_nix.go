//go:build !windows
// +build !windows

package sanitizer

import (
	"path/filepath"
	"strings"
)

var (
	nixReplacer = strings.NewReplacer(`\`, `/`)
)

func sanitizePath(in string) string {

	// normalizing path separators (something filepath.Clean will do it for us on Windows, but not
	// on the other platforms)
	in = nixReplacer.Replace(in)

	return strings.TrimPrefix(filepath.Clean(nixPathSeparator+in), nixPathSeparator)
}
