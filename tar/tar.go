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

// Package tar is a drop-in replacement for archive/tar with security focus.
//
// To prevent security implications (e.g. directory traversal) of attacker controlled crafted tar
// archives, this library sanitizes
// - file names (bugos filename entries like ../something are fixed on the fly)
// - the file mode (removing special bits like setuid)
// It also:
// - skips special file types silently (fifos, device nodes, char devices, etc.)
// - strips extended file system attributes
// - skips files that would need to be extracted through a symbolic link
//
// Features turned on by default:
// - SanitizeFilenames
// - PreventSymlinkTraversal
// These two features are compatible with all known legitimate use-cases.
//
// You may enable the other features individually like this:
// tr := tar.NewReader(buf)
// tr.SetSecurityMode(tr.GetSecurityMode() | tar.SanitizeFileMode | tar.DropXattrs)
// or
// tr.SetSecurityMode(tar.MaximumSecurityMode)
//
// You may opt out from a certain feature like this:
// tr.SetSecurityMode(tr.GetSecurityMode() &^ tar.SanitizeFileMode)
//
// Notes about PreventSymlinkTraversal. Consider the following archive:
// $ tar tvf traverse-via-links.tar
// lrwxrwxrwx username/groupname 0 2023-03-08 09:43 linktoroot -> /
// -rw-rw-r-- username/groupname 5 2023-03-08 09:44 linktoroot/root/.bashrc
//
// If an archive like this is extracted blindly, the .bashrc file of the root user would
// be overwritten. The safearchive/tar library prevents this by keeping track of symbolic links
// and not emitting entries that would need to be extracted through a symbolic link.
// This is a feature enabled by default (PreventSymlinkTraversal), as no legitimate archives should
// contain entries that are to be extracted through a symbolic link.
package tar

import (
	"archive/tar" // NOLINT
	"io"
	"io/fs"
	"strings"

	"github.com/google/safearchive/sanitizer"
)

// Format represents the tar archive format.
//
// The original tar format was introduced in Unix V7.
// Since then, there have been multiple competing formats attempting to
// standardize or extend the V7 format to overcome its limitations.
// The most common formats are the USTAR, PAX, and GNU formats,
// each with their own advantages and limitations.
//
// The following table captures the capabilities of each format:
//
//	                  |  USTAR |       PAX |       GNU
//	------------------+--------+-----------+----------
//	Name              |   256B | unlimited | unlimited
//	Linkname          |   100B | unlimited | unlimited
//	Size              | uint33 | unlimited |    uint89
//	Mode              | uint21 |    uint21 |    uint57
//	Uid/Gid           | uint21 | unlimited |    uint57
//	Uname/Gname       |    32B | unlimited |       32B
//	ModTime           | uint33 | unlimited |     int89
//	AccessTime        |    n/a | unlimited |     int89
//	ChangeTime        |    n/a | unlimited |     int89
//	Devmajor/Devminor | uint21 |    uint21 |    uint57
//	------------------+--------+-----------+----------
//	string encoding   |  ASCII |     UTF-8 |    binary
//	sub-second times  |     no |       yes |        no
//	sparse files      |     no |       yes |       yes
//
// The table's upper portion shows the Header fields, where each format reports
// the maximum number of bytes allowed for each string field and
// the integer type used to store each numeric field
// (where timestamps are stored as the number of seconds since the Unix epoch).
//
// The table's lower portion shows specialized features of each format,
// such as supported string encodings, support for sub-second timestamps,
// or support for sparse files.
//
// The Writer currently provides no support for sparse files.
type Format = tar.Format

const (
	// FormatUnknown indicates that the format is unknown.
	// @see archive/tar.FormatUnknown
	FormatUnknown = tar.FormatUnknown
	// FormatUSTAR represents the USTAR header format defined in POSIX.1-1988.
	// @see archive/tar.FormatUSTAR
	FormatUSTAR = tar.FormatUSTAR
	// FormatPAX represents the PAX header format defined in POSIX.1-2001.
	// @see archive/tar.FormatPAX
	FormatPAX = tar.FormatPAX
	// FormatGNU represents the GNU header format.
	// @see archive/tar.FormatGNU
	FormatGNU = tar.FormatGNU
)

// A Header represents a single header in a tar archive.
// Some fields may not be populated.
//
// For forward compatibility, users that retrieve a Header from Reader.Next,
// mutate it in some ways, and then pass it back to Writer.WriteHeader
// should do so by creating a new Header and copying the fields
// that they are interested in preserving.
type Header = tar.Header

// Type flags for Header.Typeflag.
const (
	// Type '0' indicates a regular file.
	TypeReg  = tar.TypeReg
	TypeRegA = tar.TypeRegA // Deprecated: Use TypeReg instead.

	// Type '1' to '6' are header-only flags and may not have a data body.
	TypeLink    = tar.TypeLink    // Hard link
	TypeSymlink = tar.TypeSymlink // Symbolic link
	TypeChar    = tar.TypeChar    // Character device node
	TypeBlock   = tar.TypeBlock   // Block device node
	TypeDir     = tar.TypeDir     // Directory
	TypeFifo    = tar.TypeFifo    // FIFO node

	// Type '7' is reserved.
	TypeCont = tar.TypeCont

	// Type 'x' is used by the PAX format to store key-value records that
	// are only relevant to the next file.
	// This package transparently handles these types.
	TypeXHeader = tar.TypeXHeader

	// Type 'g' is used by the PAX format to store key-value records that
	// are relevant to all subsequent files.
	// This package only supports parsing and composing such headers,
	// but does not currently support persisting the global state across files.
	TypeXGlobalHeader = tar.TypeXGlobalHeader

	// Type 'S' indicates a sparse file in the GNU format.
	TypeGNUSparse = tar.TypeGNUSparse

	// Types 'L' and 'K' are used by the GNU format for a meta file
	// used to store the path or link name for the next file.
	// This package transparently handles these types.
	TypeGNULongName = tar.TypeGNULongName
	TypeGNULongLink = tar.TypeGNULongLink
)

// SecurityMode controls security features to enforce
type SecurityMode int

var allowListedPaxKeys = []string{"ctime", "mtime", "atime"}

const (
	// SkipSpecialFiles security mode skips special files (e.g. block devices or fifos)
	SkipSpecialFiles SecurityMode = 1
	// SanitizeFileMode will drop special file modes (e.g. setuid and tmp bit)
	// This feature is not enabled by default.
	SanitizeFileMode SecurityMode = 2
	// SanitizeFilenames will sanitize filenames (dropping .. path components and turning entries into relative)
	// The very first version (early 2022) of this library featured this security measure only.
	// This feature is enabled by default.
	SanitizeFilenames SecurityMode = 4
	// DropXattrs will drop extended attributes from the header
	// This feature is not enabled by default.
	DropXattrs SecurityMode = 16
	// PreventSymlinkTraversal drops malicious entries that attempt to write to an outside location
	// through a symbolic link.
	// This feature is enabled by default.
	PreventSymlinkTraversal SecurityMode = 32
	// PreventCaseInsensitiveSymlinkTraversal activates case insensitive symlink traversal detection.
	// This feature requires PreventSymlinkTraversal to be enabled as well.
	// By default, this is activated only on MacOS and Windows builds. If you are extracting to a
	// case insensitive filesystem on a Unix platform, you should activate this feature explicitly.
	PreventCaseInsensitiveSymlinkTraversal SecurityMode = 64
	// SkipWindowsShortFilenames drops archive entries that have a path component that look like a
	// Windows short filename (e.g. GIT~1).
	// By default, this is activated only on Windows builds. If you are extracting to a Windows
	// filesystem on a non-Windows platform, you should activate this feature explicitly.
	SkipWindowsShortFilenames SecurityMode = 128
)

// MaximumSecurityMode enables all features for maximum security.
// Recommended for integrations that need file contents only (and nothing unix specific).
const MaximumSecurityMode = SkipSpecialFiles | SanitizeFileMode | SanitizeFilenames | PreventSymlinkTraversal | DropXattrs | PreventCaseInsensitiveSymlinkTraversal | SkipWindowsShortFilenames

var (
	// ErrHeader invalid tar header
	ErrHeader = tar.ErrHeader

	// ErrWriteTooLong write too long
	ErrWriteTooLong = tar.ErrWriteTooLong

	// ErrFieldTooLong header field too long
	ErrFieldTooLong = tar.ErrFieldTooLong

	// ErrWriteAfterClose write after close
	ErrWriteAfterClose = tar.ErrWriteAfterClose
)

// Writer provides sequential writing of a tar archive.
// Write.WriteHeader begins a new file with the provided Header,
// and then Writer can be treated as an io.Writer to supply that file's data.
type Writer = tar.Writer

// NewWriter creates a new Writer writing to w.
func NewWriter(w io.Writer) *tar.Writer {
	return tar.NewWriter(w)
}

// FileInfoHeader creates a partially-populated Header from fi.
// If fi describes a symlink, FileInfoHeader records link as the link target.
// If fi describes a directory, a slash is appended to the name.
//
// Since fs.FileInfo's Name method only returns the base name of
// the file it describes, it may be necessary to modify Header.Name
// to provide the full path name of the file.
func FileInfoHeader(fi fs.FileInfo, link string) (*Header, error) {
	return tar.FileInfoHeader(fi, link)
}

// Reader provides sequential access to the contents of a tar archive.
// Reader.Next advances to the next file in the archive (including the first),
// and then Reader can be treated as an io.Reader to access the file's data.
type Reader struct {
	unsafeReader *tar.Reader

	securityMode SecurityMode
	symlinks     map[string]bool
}

// NewReader creates a new Reader reading from r.
func NewReader(r io.Reader) *Reader {
	re := Reader{unsafeReader: tar.NewReader(r)}
	re.securityMode = DefaultSecurityMode
	re.symlinks = make(map[string]bool)
	return &re
}

func leaveKeys(in map[string]string, allowListedKeys ...string) map[string]string {
	re := map[string]string{}
	for inK, inV := range in {
		for _, alK := range allowListedKeys {
			if alK == inK {
				re[inK] = inV
				break
			}
		}
	}
	return re
}

// SetSecurityMode controls the security features applied when reading this tar archive
func (tr *Reader) SetSecurityMode(s SecurityMode) {
	tr.securityMode = s
}

// GetSecurityMode returns the currently enabled security features
func (tr *Reader) GetSecurityMode() SecurityMode {
	return tr.securityMode
}

// Next advances to the next entry in the tar archive.
// The Header.Size determines how many bytes can be read for the next file.
// Any remaining data in the current file is automatically discarded.
//
// io.EOF is returned at the end of the input.
func (tr *Reader) Next() (*tar.Header, error) {
	for {
		h, err := tr.unsafeReader.Next()
		if err != nil {
			return h, err
		}

		if tr.securityMode&SkipSpecialFiles != 0 {
			// non-safe entries are skipped
			if h.Typeflag != TypeReg && h.Typeflag != TypeDir && h.Typeflag != TypeSymlink {
				continue
			}
		}

		if tr.securityMode&SanitizeFileMode != 0 {
			// clearing out any potentially special bits (e.g. setuid)
			h.Mode = h.Mode & 0777 // &^ s_ISUID &^ s_ISGID &^ s_ISVTX
		}

		if tr.securityMode&SanitizeFilenames != 0 {
			// Sanitize h.Name
			h.Name = sanitizer.SanitizePath(h.Name)
		}

		if tr.securityMode&SkipWindowsShortFilenames != 0 && sanitizer.HasWindowsShortFilenames(h.Name) {
			continue
		}

		if tr.securityMode&PreventSymlinkTraversal != 0 {
			hName := sanitizer.SanitizePath(h.Name)
			hName = strings.TrimSuffix(hName, "/")
			if tr.securityMode&PreventCaseInsensitiveSymlinkTraversal != 0 {
				hName = strings.ToLower(hName)
			}

			n := strings.Split(hName, "/")
			traversal := false
			for i := 1; i <= len(n); i++ {
				subPath := strings.Join(n[0:i], "/")
				if tr.symlinks[subPath] {
					// a symlink has already been seen on this path. We need to drop this entry.
					traversal = true
					break
				}
			}
			if traversal {
				continue
			}
			if h.Linkname != "" {
				tr.symlinks[hName] = true
			}
		}

		if tr.securityMode&DropXattrs != 0 {
			// Dropping extended attributes, if present
			h.Xattrs = nil
			h.PAXRecords = leaveKeys(h.PAXRecords, allowListedPaxKeys...)
		}

		return h, err
	}
}

// Read reads from the current file in the tar archive.
// It returns (0, io.EOF) when it reaches the end of that file,
// until Next is called to advance to the next file.
//
// If the current file is sparse, then the regions marked as a hole
// are read back as NUL-bytes.
//
// Calling Read on special types like TypeLink, TypeSymlink, TypeChar,
// TypeBlock, TypeDir, and TypeFifo returns (0, io.EOF) regardless of what
// the Header.Size claims.
func (tr *Reader) Read(b []byte) (int, error) {
	return tr.unsafeReader.Read(b)
}
