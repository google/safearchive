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

package tar

import (
	"archive/tar"
	"bytes"
	_ "embed"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	// Archive containing files: readme.txt, /gopher.txt, and ../todo.txt
	//go:embed traverse.tar
	eTraverseTar []byte

	/*
	   $ tar tvf traverse-via-links.tar
	   lrwxrwxrwx imrer/primarygroup 0 2023-03-08 09:43 linktoroot -> /
	   -rw-rw-r-- imrer/primarygroup 5 2023-03-08 09:44 linktoroot/root/.bashrc
	   lrwxrwxrwx imrer/primarygroup 0 2023-03-08 09:46 linktoescape -> ../outside.txt
	   -rw-rw-r-- imrer/primarygroup 6 2023-03-08 09:46 linktoescape
	*/
	//go:embed traverse-via-links.tar
	eTraverseViaLinksTar []byte

	/*
		$ tar tvf traverse-slash-at-the-end.tar
		lrwxrwxrwx imrer/primarygroup 0 2023-03-23 13:28 linktoroot/ -> /
		-rw-r----- imrer/primarygroup 5 2023-03-23 13:28 linktoroot/root/.bashrc
	*/
	//go:embed traverse-slash-at-the-end.tar
	eTraverseSlashAtTheEndTar []byte

	/*
	   The input archive we are testing looks like this:
	   $ tar tvf specialfiles.tar
	   prw-r----- imrer/primarygroup 0 2023-03-08 13:36 fifo
	   crw-r--r-- root/root        1,3 2023-03-08 13:37 null
	   brw-r--r-- root/root        8,0 2023-03-08 13:39 sda
	   drwxr-x--- imrer/primarygroup 0 2023-03-08 13:41 dir/
	   -rw-r----- imrer/primarygroup 8 2023-03-08 13:38 regular.txt
	   lrwxrwxrwx imrer/primarygroup 0 2023-03-08 13:41 symlink -> regular.txt
	   hrw-r----- imrer/primarygroup 0 2023-03-08 13:38 hardlink link to regular.txt
	*/
	//go:embed specialfiles.tar
	eSpecialFilesTar []byte

	/*
		The input archive we are testing looks like this:
		$ tar tvf specialmodes.tar
		-rwSr-S--- imrer/primarygroup 12 2023-03-08 13:55 setuidstuff.txt
		-rwsr-s--- imrer/primarygroup 13 2023-03-08 13:55 setuidstuff2.txt
		-rw-r----T imrer/primarygroup  9 2023-03-08 13:55 tmpstuff.txt
		drwxr-x--- imrer/primarygroup  0 2023-03-09 08:23 somedir/
	*/
	//go:embed specialmodes.tar
	eSpecialModesTar []byte

	/*
	 archive normally containing:
	 2023/03/08 15:35:39 Contents of &{Typeflag:48 Name:something.txt Linkname: Size:10 Mode:416 Uid:1040569 Gid:89939
	 Uname:imrer Gname:primarygroup ModTime:2023-03-08 15:29:32.94598663 +0000 UTC
	 AccessTime:2023-03-08 15:29:32.94598663 +0000 UTC ChangeTime:2023-03-08 15:29:52.687447969 +0000 UTC
	 Devmajor:0 Devminor:0 Xattrs:map[user.hello:world]
	 PAXRecords:map[SCHILY.xattr.user.hello:world
	 atime:1678289372.94598663 ctime:1678289392.687447969 mtime:1678289372.94598663] Format:PAX}:
	*/
	//go:embed xattr.tar
	eXattrTar []byte

	/*
	   lrwxrwxrwx root/root         0 2024-10-10 11:17 tmp -> /
	   -rw-r--r-- root/root         5 2024-10-10 11:17 Tmp/test-file
	*/
	//go:embed case-insensitive.tar
	eTraverseViaCaseInsensitiveLinksTar []byte
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

// Based on example from: https://pkg.go.dev/archive/tar#pkg-overview
func TestSafetar(t *testing.T) {
	buf := bytes.NewBuffer(eTraverseTar[:])

	// Open and iterate through the files in the archive.
	tr := NewReader(buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(hdr.Name, "/") {
			t.Errorf("hdr.Name has unwanted '/' prefix: %q", hdr.Name)
		}
		if containsDotDot(hdr.Name) {
			t.Errorf("hdr.Name contains unwanted '..': %q", hdr.Name)
		}
	}
}

func TestSafetarLinksDefaultMode(t *testing.T) {
	buf := bytes.NewBuffer(eTraverseViaLinksTar[:])

	// default settings with PreventSymlinkTraversal
	tr := NewReader(buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// first entry is supposed to be linktoroot/root/.bashrc (linktoroot symlink skipped)
	if hdr.Name != "linktoroot" {
		t.Errorf("unexpected 1st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 1st entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "/" {
		t.Errorf("unexpected 1st entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "linktoescape" {
		t.Errorf("unexpected 2nd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 2nd entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "../outside.txt" {
		t.Errorf("unexpected 2nd entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("unexpected entry: %v", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestSafetarLinksDefaultModeSlashAtTheEnd(t *testing.T) {
	// note the commend at sanitizePath:
	// "Add back trailing / if safe"
	// this test ensures the PreventSymlinkTraversal security check cannot be bypassed via
	// entries ending with slash

	buf := bytes.NewBuffer(eTraverseSlashAtTheEndTar[:])

	// default settings with PreventSymlinkTraversal
	tr := NewReader(buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// first entry is supposed to be linktoroot/root/.bashrc (linktoroot symlink skipped)
	if hdr.Name != "linktoroot/" {
		t.Errorf("unexpected 1st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 1st entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "/" {
		t.Errorf("unexpected 1st entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("unexpected entry: %v", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestSafetarLinksWithoutSanitization(t *testing.T) {
	buf := bytes.NewBuffer(eTraverseViaLinksTar[:])

	// Open and iterate through the files in the archive.
	tr := NewReader(buf)
	tr.SetSecurityMode(tr.GetSecurityMode() &^ PreventSymlinkTraversal)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// first entry is supposed to be linktoroot pointing to the root
	if hdr.Name != "linktoroot" {
		t.Errorf("unexpected 1st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 1st entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "/" {
		t.Errorf("unexpected 1st entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "linktoroot/root/.bashrc" {
		t.Errorf("unexpected 2nd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 2nd entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "" {
		t.Errorf("unexpected 2nd entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "linktoescape" {
		t.Errorf("unexpected 3rd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 3rd entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "../outside.txt" {
		t.Errorf("unexpected 3rd entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "linktoescape" {
		t.Errorf("unexpected 4th entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 4th entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "" {
		t.Errorf("unexpected 4th entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("unexpected entry: %v", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestSpecialFiles(t *testing.T) {
	buf := bytes.NewBuffer(eSpecialFilesTar[:])

	// Open and iterate through the files in the archive.
	tr := NewReader(buf)
	tr.SetSecurityMode(tr.GetSecurityMode() | SkipSpecialFiles)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	if hdr.Name != "dir/" {
		t.Errorf("unexpected 1st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeDir {
		t.Errorf("unexpected 1st entry type: %v", hdr.Typeflag)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "regular.txt" {
		t.Errorf("unexpected 2nd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 2nd entry type: %v", hdr.Typeflag)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "symlink" {
		t.Errorf("unexpected 3rd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeSymlink {
		t.Errorf("unexpected 3rd entry type: %v", hdr.Typeflag)
	}
	if hdr.Linkname != "regular.txt" {
		t.Errorf("unexpected 3rd entry Linkname: %v", hdr.Linkname)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("unexpected entry: %v", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}

func TestSpecialModes(t *testing.T) {
	buf := bytes.NewBuffer(eSpecialModesTar[:])

	// Open and iterate through the files in the archive.
	tr := NewReader(buf)
	tr.SetSecurityMode(tr.GetSecurityMode() | SanitizeFileMode)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	if hdr.Name != "setuidstuff.txt" {
		t.Errorf("unexpected 1st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 1st entry type: %v", hdr.Typeflag)
	}
	if hdr.Mode != 0640 {
		t.Errorf("unexpected 1st entry mode: %v", hdr.Mode)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "setuidstuff2.txt" {
		t.Errorf("unexpected 2nd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 2nd entry type: %v", hdr.Typeflag)
	}
	if hdr.Mode != 0750 {
		t.Errorf("unexpected 2nd entry mode: %v", hdr.Mode)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "tmpstuff.txt" {
		t.Errorf("unexpected 3rd entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeReg {
		t.Errorf("unexpected 3rd entry type: %v", hdr.Typeflag)
	}
	if hdr.Mode != 0640 {
		t.Errorf("unexpected 3rd entry mode: %v", hdr.Mode)
	}

	hdr, err = tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "somedir/" {
		t.Errorf("unexpected 4st entry: %q", hdr.Name)
	}
	if hdr.Typeflag != TypeDir {
		t.Errorf("unexpected 4st entry type: %v", hdr.Typeflag)
	}
	if hdr.Mode != 0750 {
		t.Errorf("unexpected 4st entry mode: %v", hdr.Mode)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("unexpected entry: %v", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}

func testLeaveKeys(t *testing.T) {
	m := map[string]string{"foo": "bar", "Foo": "Bar"}
	n := leaveKeys(m, "foo")
	if !reflect.DeepEqual(n, map[string]string{"foo": "bar"}) {
		t.Errorf("function leaveKeys unexpected return: %v", n)
	}
}

// why isn't this part of golang core?
func contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func TestXattrs(t *testing.T) {
	buf := bytes.NewBuffer(eXattrTar[:])

	// Open and iterate through the files in the archive.
	members := 0
	tr := NewReader(buf)
	tr.SetSecurityMode(tr.GetSecurityMode() | DropXattrs)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			t.Fatal(err)
		}
		members++
		if hdr.Name != "something.txt" {
			t.Errorf("hdr.Name is unexpected: %q", hdr.Name)
		}
		if hdr.Xattrs != nil {
			t.Errorf("hdr.Xattrs is non-nil: %+v", hdr.Xattrs)
		}
		if hdr.PAXRecords != nil {
			for _, k := range allowListedPaxKeys {
				if hdr.PAXRecords[k] == "" {
					t.Errorf("%s in hdr.PAXRecords is empty", k)
				}
			}
			for k := range hdr.PAXRecords {
				if !contains(allowListedPaxKeys, k) {
					t.Errorf("unexpected item in PAXRecords: %v", k)
				}
			}
		} else {
			t.Errorf("hdr.PAXRecords is nil")
		}
	}

	if members != 1 {
		t.Errorf("the Reader didn't yield any members")
	}
}

func TestSafetarLinksCaseInsensitive(t *testing.T) {
	buf := bytes.NewBuffer(eTraverseViaCaseInsensitiveLinksTar[:])

	// default settings with PreventSymlinkTraversal
	tr := NewReader(buf)
	tr.SetSecurityMode(tr.GetSecurityMode() | PreventCaseInsensitiveSymlinkTraversal)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// first entry is supposed to be tmp -> /
	want := &tar.Header{Name: "tmp", Typeflag: TypeSymlink, Linkname: "/"}
	opts := cmpopts.IgnoreFields(tar.Header{}, "Mode", "Uname", "Gname", "ModTime", "Format")
	if diff := cmp.Diff(hdr, want, opts); diff != "" {
		t.Errorf("Next() returned unexpected diff (-want +got):\n%s", diff)
	}

	hdr, err = tr.Next()
	if hdr != nil {
		t.Errorf("No more tar entries were expected. Next() = %+v, want nil", hdr)
	}
	if err != io.EOF {
		t.Fatal(err)
	}
}
