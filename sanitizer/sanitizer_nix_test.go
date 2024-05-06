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

//go:build !windows
// +build !windows

package sanitizer

import (
	"testing"
)

func TestSanitizePathUnix(t *testing.T) {
	type testCase struct {
		input, expected string
	}

	testCases := map[string][]testCase{
		"AbsolutePaths": []testCase{
			{"/some/thing", `some/thing`},
			{`C:\some\thing`, `C:/some/thing`},
			{`c:\some\thing`, `c:/some/thing`},
			{`C:/some/thing`, `C:/some/thing`},
			{`\some\thing`, `some/thing`},
		},
		"UNCPaths": []testCase{
			{`\\FILESHARE\stuff\thing`, `FILESHARE/stuff/thing`},
			{`//FILESHARE/stuff/thing`, `FILESHARE/stuff/thing`},
		},
		"BackslashBackslashSpecial": []testCase{
			{`\\.\C:\some\path`, `C:/some/path`},
			{`//./C:/some\path`, `C:/some/path`},
			{`/\.\C:\some\path`, `C:/some/path`},
			{`\\?\Volume{96f0460f-a710-40e3-ad53-76530201cf29}\some.txt`, `?/Volume{96f0460f-a710-40e3-ad53-76530201cf29}/some.txt`},
		},
		"AlternativeDataStreams": []testCase{
			{`something.txt:alternate`, `something.txt:alternate`},
			{`something.txt::$DATA`, `something.txt::$DATA`},
		},
		"ReservedFilenames": []testCase{
			{`somedir\LPT1`, `somedir/LPT1`},
			{`somedir\LPT1\somefile`, `somedir/LPT1/somefile`},
		},
		"RelativePaths": []testCase{
			{`../../some/thing`, `some/thing`},
			{`../../some/thing`, `some/thing`},
			{`..\..\some\thing`, `some/thing`},
		},
		"TrailingSlash": []testCase{
			{`some/path/`, `some/path/`},
			{`some/path\`, `some/path/`},
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
