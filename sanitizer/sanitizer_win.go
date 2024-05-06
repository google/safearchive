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

//go:build windows
// +build windows

package sanitizer

import (
	"path/filepath"
	"strings"
)

var (
	replacer = strings.NewReplacer(`:`, `\`, `/`, `\`, `?`, `\`)

	ss1 = "\u00B9" // Superscript One https://www.compart.com/en/unicode/U+00B9
	ss2 = "\u00B2" // Superscript Two https://www.compart.com/en/unicode/U+00B2
	ss3 = "\u00B3" // Superscript Three https://www.compart.com/en/unicode/U+00B3
)

// isReservedName reports if name is a Windows reserved device name or a console handle.
// It does not detect names with an extension, which are also reserved on some Windows versions.
//
// For details, search for PRN in
// https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file.
//
// This is borrowed from https://github.com/golang/go/blob/master/src/path/filepath/path_windows.go
// and fixed.
func isReservedName(name string) bool {
	nameLen := len(name)
	if nameLen < 3 {
		return false
	}

	reservedNameLen := 0
	prefix := strings.ToUpper(name[0:3])
	switch prefix {
	case "CON":
		reservedNameLen = 3

		// Passing CONIN$ or CONOUT$ to CreateFile opens a console handle.
		// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#consoles
		//
		// While CONIN$ and CONOUT$ aren't documented as being files,
		// they behave the same as CON. For example, ./CONIN$ also opens the console input.

		if nameLen >= 6 && name[5] == '$' && strings.EqualFold(name[3:6], "IN$") {
			reservedNameLen += 3
		}
		if nameLen >= 7 && name[6] == '$' && strings.EqualFold(name[3:7], "OUT$") {
			reservedNameLen += 4
		}

	case "PRN", "AUX", "NUL":
		reservedNameLen = 3
	case "COM", "LPT":
		// these two reserved names must be followed by a digit or a SUPERSCRIPT
		if nameLen >= 4 {
			switch name[3] {
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				reservedNameLen = 4
			case ss1[0]: // unicode
				if nameLen >= 5 {
					switch name[4] {
					case ss1[1], ss2[1], ss3[1]:
						reservedNameLen = 5
					}
				}
			}
		}
	}

	// All the reserved names may be followed by optional whitespaces
	if reservedNameLen != 0 && strings.TrimSpace(name[reservedNameLen:]) == "" {
		return true
	}

	return false
}

func sanitizePath(in string) string {
	// we get rid of : (ADS or drive letter specifier)
	in = replacer.Replace(in)

	// note: we do clean(trim(clean())) so even weird syntax like \\.\C:\something is sanitized safely
	tmp := filepath.Clean(strings.TrimLeft(filepath.Clean(winPathSeparator+in), winPathSeparator))

	sb := strings.Builder{}

	// time to deal with reserved path components (e.g. LPT1), if any
	// at this point, the path separators in tmp are already normalized (\)
	first := true
	for p := tmp; p != ""; {
		var part string
		part, p, _ = strings.Cut(p, winPathSeparator)
		// Trim the extension and look for a reserved name.
		base, ext, _ := strings.Cut(part, ".")
		if first {
			first = false
		} else {
			sb.WriteString(winPathSeparator)
		}
		sb.WriteString(base)
		if isReservedName(base) {
			sb.WriteString("-safe")
		}
		if ext != "" {
			sb.WriteString(".")
			sb.WriteString(ext)
		}
	}

	return sb.String()
}
