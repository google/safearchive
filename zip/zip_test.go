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

package zip

import (
	"bytes"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

// Check whether a path contains .. entries
func containsDotDot(v string) bool {
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

var (
	// Archive containing files: ../traverse, /absolute
	//go:embed archive.zip
	eArchiveZip []byte

	// Zip archive containing symbolic links
	//go:embed symlinks.zip
	eSymlinksZip []byte

	// Zip archive containing files with special file modes
	//go:embed specialmodes.zip
	eSpecialModesZip []byte

	/*
		// this archive looks like this:
				$ unzip -l symlinks2.zip
			Archive:  symlinks2.zip
			  Length      Date    Time    Name
			---------  ---------- -----   ----
			        1  2023-03-23 15:12   root
			        5  2023-03-23 15:12   root/poc.txt
			---------                     -------
			        6                     2 files

			the entry with name root is a symbolic link pointing to /root
	*/
	//go:embed symlinks2.zip
	eSymlinks2Zip []byte

	/*
		// Same as the previous, but the root entry has a slash at the end:
		Archive:  symlinks3.zip
		  Length      Date    Time    Name
		---------  ---------- -----   ----
		        1  2023-03-23 15:18   root/
		        5  2023-03-23 15:18   root/poc.txt
		---------                     -------
		        6                    2 files

	*/
	//go:embed symlinks3.zip
	eSymlinks3Zip []byte
)

func TestSafezip(t *testing.T) {
	r, err := NewReader(bytes.NewReader(eArchiveZip), int64(len(eArchiveZip)))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}

	if len(r.File) != 2 {
		t.Fatalf("unexpected number of files in the archive: %d", len(r.File))
	}

	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "/") {
			t.Errorf("f.Name has unwanted '/' prefix: %q", f.Name)
		}
		if containsDotDot(f.Name) {
			t.Errorf("f.Name contains unwanted '..': %q", f.Name)
		}
	}
}

func commonTestsBefore(t *testing.T, files []*File) {
	if len(files) != 2 {
		t.Fatalf("unexpected number of files in the archive (before): %d", len(files))
	}

	if containsDotDot(files[0].Name) {
		t.Errorf("f.Name contains unwanted '..': %q", files[0].Name)
	}
	if strings.HasPrefix(files[1].Name, "/") {
		t.Errorf("f.Name has unwanted '/' prefix: %q", files[1].Name)
	}

}

func commonTestsAfter(t *testing.T, files []*File) {
	if len(files) != 2 {
		t.Fatalf("unexpected number of files in the archive (after): %d", len(files))
	}

	if !containsDotDot(files[0].Name) {
		t.Errorf("f.Name doesn't contain unwanted '..': %q", files[0].Name)
	}
	if !strings.HasPrefix(files[1].Name, "/") {
		t.Errorf("f.Name does not have unwanted '/' prefix: %q", files[1].Name)
	}

}

func TestSetSecurityModeNewReader(t *testing.T) {
	// Archive containing files: ../traverse, /absolute
	r, err := NewReader(bytes.NewReader(eArchiveZip), int64(len(eArchiveZip)))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}

	commonTestsBefore(t, r.File)
	r.SetSecurityMode(DefaultSecurityMode &^ SanitizeFilenames)
	commonTestsAfter(t, r.File)
}

func archiveToPath(t *testing.T, archive []byte) string {
	t.Helper()

	tmpdir := t.TempDir()
	p := filepath.Join(tmpdir, "tmp.zip")
	err := os.WriteFile(p, archive, 0o644)
	if err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", p, err)
	}
	return p
}

func TestSetSecurityModeOpenReader(t *testing.T) {
	// Archive containing files: ../traverse, /absolute
	p := archiveToPath(t, eArchiveZip)

	r, err := OpenReader(p)
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	commonTestsBefore(t, r.File)
	r.SetSecurityMode(DefaultSecurityMode &^ SanitizeFilenames)
	commonTestsAfter(t, r.File)
}

func TestSymlinks(t *testing.T) {
	r, err := OpenReader(archiveToPath(t, eSymlinksZip))
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	if len(r.File) != 1 {
		t.Fatalf("we expected the symlink entry to be present, but it wasnt: %d", len(r.File))
	}
	if r.File[0].Name != "thisisalink.txt" {
		t.Fatalf("unexpected entry: %q", r.File[0].Name)
	}

	r.SetSecurityMode(DefaultSecurityMode &^ PreventSymlinkTraversal)

	if len(r.File) != 1 {
		t.Fatalf("symlink check disabled, symlink entry should show up, but it didn't: %d", len(r.File))
	}
	if r.File[0].Name != "thisisalink.txt" {
		t.Fatalf("unexpected entry: %q", r.File[0].Name)
	}
}

func TestSpecialModes(t *testing.T) {
	r, err := OpenReader(archiveToPath(t, eSpecialModesZip))
	r.SetSecurityMode(r.GetSecurityMode() | SanitizeFileMode)
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	if len(r.File) != 4 {
		t.Fatalf("we expected all entries: %d", len(r.File))
	}

	if r.File[0].Name != "setuidstuff.txt" {
		t.Errorf("unexpected 1st entry: %s", r.File[0].Name)
	}
	if r.File[0].Mode() != 0640 {
		t.Errorf("unexpected 1st entry file mode: %d", r.File[0].Mode())
	}

	if r.File[1].Name != "setuidstuff2.txt" {
		t.Errorf("unexpected 2nd entry: %s", r.File[1].Name)
	}
	if r.File[1].Mode() != 0750 {
		t.Errorf("unexpected 2nd entry file mode: %d", r.File[1].Mode())
	}

	if r.File[2].Name != "tmpstuff.txt" {
		t.Errorf("unexpected 3rd entry: %s", r.File[2].Name)
	}
	if r.File[2].Mode() != 0640 {
		t.Errorf("unexpected 3rd entry file mode: %d", r.File[2].Mode())
	}

	if r.File[3].Name != "somedir/" {
		t.Errorf("unexpected 4th entry: %s", r.File[3].Name)
	}
	if r.File[3].Mode() != (fs.ModeDir | 0750) {
		t.Errorf("unexpected 4th entry file mode: %d", r.File[3].Mode())
	}

	// now assessing how these entries would have looked like if we didn't sanitize them:
	r.SetSecurityMode(DefaultSecurityMode &^ SanitizeFileMode)

	if len(r.File) != 4 {
		t.Fatalf("we expected all entries, still: %d", len(r.File))
	}

	if r.File[0].Name != "setuidstuff.txt" {
		t.Errorf("unexpected 1st entry: %s", r.File[0].Name)
	}
	if r.File[0].Mode() != (fs.ModeSetuid | fs.ModeSetgid | 0640) {
		t.Errorf("unexpected 1st entry file mode: %d", r.File[0].Mode())
	}

	if r.File[1].Name != "setuidstuff2.txt" {
		t.Errorf("unexpected 2nd entry: %s", r.File[1].Name)
	}
	if r.File[1].Mode() != (fs.ModeSetuid | fs.ModeSetgid | 0750) {
		t.Errorf("unexpected 2nd entry file mode: %d", r.File[1].Mode())
	}

	if r.File[2].Name != "tmpstuff.txt" {
		t.Errorf("unexpected 3rd entry: %s", r.File[2].Name)
	}
	if r.File[2].Mode() != (fs.ModeSticky | 0640) {
		t.Errorf("unexpected 3rd entry file mode: %d", r.File[2].Mode())
	}

	if r.File[3].Name != "somedir/" {
		t.Errorf("unexpected 4th entry: %s", r.File[3].Name)
	}
	if r.File[3].Mode() != (fs.ModeDir | 0750) {
		t.Errorf("unexpected 4th entry file mode: %d", r.File[3].Mode())
	}
}

func TestSymlinks2(t *testing.T) {
	r, err := OpenReader(archiveToPath(t, eSymlinks2Zip))
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	if len(r.File) != 1 {
		t.Fatalf("we expected the symlink entry to be present, but not the follow up entry: %d", len(r.File))
	}
	if r.File[0].Name != "root" {
		t.Errorf("unexpected entry: %q", r.File[0].Name)
	}
}

func TestSymlinks3(t *testing.T) {
	r, err := OpenReader(archiveToPath(t, eSymlinks3Zip))
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	if len(r.File) != 1 {
		t.Fatalf("we expected the symlink entry to be present, but not the follow up entry: %d", len(r.File))
	}
	if r.File[0].Name != "root/" {
		t.Errorf("unexpected entry: %q", r.File[0].Name)
	}
}

func TestTypes(t *testing.T) {
	archivePath := archiveToPath(t, eArchiveZip)
	archive := eArchiveZip

	r1, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip.NewReader() error = %v", err)
	}
	newReaderType := fmt.Sprintf("%T", r1)

	r2, err := OpenReader(archivePath)
	if err != nil {
		t.Fatalf("zip.OpenReader() error = %v", err)
	}

	openReaderType := fmt.Sprintf("%T", r2.Reader)

	if "*"+openReaderType != newReaderType {
		t.Errorf("type of zip.OpenReader().Reader: %v, type of zip.NewReader(): %v", openReaderType, newReaderType)
	}
}
