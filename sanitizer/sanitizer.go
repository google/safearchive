// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sanitizer is a lightweight library that facilitates the safearchive libraries to
// prevent path traversal attempts by sanitize file paths.
package sanitizer

import (
	"os"
	"regexp"
	"strings"
)

const (
	winPathSeparator = `\`
	nixPathSeparator = `/`
)

var (
	winShortFilenameRegex = regexp.MustCompile(`~\d+\.?`)
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

// HasWindowsShortFilenames reports if any path component look like a Windows short filename.
// Short filenames on Windows may look like this:
// 1(3)~1.PNG     1 (3) (1).png
// DOWNLO~1       Downloads
// FOOOOO~1.JPG   fooooooooo.png.gif.jpg
func HasWindowsShortFilenames(in string) bool {
	in = strings.ReplaceAll(in, "\\", "/")
	parts := strings.Split(in, "/")
	for _, part := range parts {
		matched := winShortFilenameRegex.MatchString(part)
		if matched {
			return true
		}
	}
	return false
}
