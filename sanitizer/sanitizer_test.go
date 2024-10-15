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

package sanitizer

import (
	"strings"
	"testing"
)

func TestHasWindowsShortFilenames(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{in: "ANDROI~2", want: true},
		{in: "foo/ANDROI~2", want: true},
		{in: "ANDROI~2/bar", want: true},
		{in: "foo/ANDROI~2/bar", want: true},
		// Same with different case
		{in: "Androi~2", want: true},
		{in: "foo/Androi~2", want: true},
		{in: "Androi~2/bar", want: true},
		{in: "foo/Androi~2/bar", want: true},
		// File extension
		{in: "FOOOOO~1.JPG ", want: true},
		{in: "foo/FOOOOO~1.JPG", want: true},
		{in: "FOOOOO~1.JPG/bar", want: true},
		{in: "foo/FOOOOO~1.JPG/bar", want: true},
		// Not a short filename
		{in: "3D Objects", want: false},
		{in: "Some~Stuff", want: false},
	}
	for _, tc := range tests {
		for _, a := range []string{tc.in, strings.ReplaceAll(tc.in, "\\", "/")} {
			got := HasWindowsShortFilenames(a)
			if got != tc.want {
				t.Errorf("HasWindowsShortFilenames(%q) = %v, want %v", a, got, tc.want)
			}
		}
	}
}
