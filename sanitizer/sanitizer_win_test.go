// Copyright 2023 Google LLC.
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
	"testing"
)

func TestSanitizePathWindows(t *testing.T) {
	type testCase struct {
		input, expected string
	}

	testCases := map[string][]testCase{
		"AbsolutePaths": []testCase{
			{"/some/thing", `some\thing`},
			{`C:\some\thing`, `C\some\thing`},
			{`c:\some\thing`, `c\some\thing`},
			{`C:/some/thing`, `C\some\thing`},
			{`\some\thing`, `some\thing`},
		},
		"FileExtensions": []testCase{
			{`some.txt\thing`, `some.txt\thing`},
			{`some.ext1.ext2\thing`, `some.ext1.ext2\thing`},
			{`some.ext1.ext2`, `some.ext1.ext2`},
			{`some.txt`, `some.txt`},
		},
		"UNCPaths": []testCase{
			{`\\FILESHARE\stuff\thing`, `FILESHARE\stuff\thing`},
			{`//FILESHARE/stuff/thing`, `FILESHARE\stuff\thing`},
		},
		"BackslashBackslashSpecial": []testCase{
			{`\\.\C:\some\path`, `C\some\path`},
			{`//./C:/some\path`, `C\some\path`},
			{`/\.\C:\some\path`, `C\some\path`},
			{`\\?\Volume{96f0460f-a710-40e3-ad53-76530201cf29}\some.txt`, `Volume{96f0460f-a710-40e3-ad53-76530201cf29}\some.txt`},
		},
		"NTprefix": []testCase{
			{`\??\C:\some\path`, `C\some\path`},
			{`\??\Volume{96f0460f-a710-40e3-ad53-76530201cf29}\some.txt`, `Volume{96f0460f-a710-40e3-ad53-76530201cf29}\some.txt`},
		},
		"AlternativeDataStreams": []testCase{
			{`something.txt:alternate`, `something.txt\alternate`},
			{`something.txt::$DATA`, `something.txt\$DATA`},
		},
		"ReservedFilenames": []testCase{
			{`somedir\LPT` + ss1, `somedir\LPT` + ss1 + `-safe`},
			{`somedir\LPT` + ss2, `somedir\LPT` + ss2 + `-safe`},
			{`somedir\LPT` + ss3, `somedir\LPT` + ss3 + `-safe`},
			{`somedir\CONIN$`, `somedir\CONIN$-safe`},
			{`somedir\CONIN$ `, `somedir\CONIN$ -safe`},
			{`somedir\CONIN$ .txt`, `somedir\CONIN$ -safe.txt`},
			{`somedir\CONOUT$`, `somedir\CONOUT$-safe`},
			{`somedir\CONOUT$ `, `somedir\CONOUT$ -safe`},
			{`somedir\CONOUT$ .txt`, `somedir\CONOUT$ -safe.txt`},
			{`somedir\LPT1`, `somedir\LPT1-safe`},
			{`somedir\LPT1.foo`, `somedir\LPT1-safe.foo`},
			{`somedir\LPT1 .foo`, `somedir\LPT1 -safe.foo`},
			{`somedir\LPT1     .foo`, `somedir\LPT1     -safe.foo`},
			{`somedir\LPT` + ss1 + ` .foo`, `somedir\LPT` + ss1 + ` -safe.foo`},
			{`somedir\LPT1\somefile`, `somedir\LPT1-safe\somefile`},
			{`somedir\LPT1.foo\somefile`, `somedir\LPT1-safe.foo\somefile`},
			{`somedir\LPT1 .foo\somefile`, `somedir\LPT1 -safe.foo\somefile`},
			{`somedir\LPT` + ss1 + `\somefile`, `somedir\LPT` + ss1 + `-safe\somefile`},
		},
		"RelativePaths": []testCase{
			{`../../some/thing`, `some\thing`},
			{`../../some/thing`, `some\thing`},
			{`..\..\some\thing`, `some\thing`},
		},
		"QuestionMark": []testCase{
			{`some?.txt`, `some\.txt`},
			{`some.txt?`, `some.txt`},
		},
		"TrailingSlash": []testCase{
			{`some\path/`, `some\path\`},
			{`some\path\`, `some\path\`},
		},
	}

	for testName, tests := range testCases {
		t.Run(testName, func(t *testing.T) {
			for _, tc := range tests {
				sanitized := SanitizePath(tc.input)
				if tc.expected != sanitized {
					t.Errorf("SanitizePath(%q) = %q, want %q", tc.input, sanitized, tc.expected)
				}
			}
		})
	}
}
