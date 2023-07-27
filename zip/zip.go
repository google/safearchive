// Package zip is a drop-in replacement for archive/zip which security focus.
//
// To prevent security implications (e.g. directory traversal) of attacker controlled crafted zip
// archives, this library sanitizes
// - file names (bugos filename entries like ../something are fixed on the fly)
// - the file mode (removing special bits like setuid)
// It also:
// - skips symbolic link entries
// - skips special file types silently (fifos, device nodes, char devices, etc.)
//
// All these features are enabled by default and can be turned off one-by-one via the SetSecurityMode
// method of the Reader/ReadCloser.
//
// Features turned on by default:
// - SanitizeFilenames
// - PreventSymlinkTraversal
// These two features are compatible with all known legitimate use-cases.
//
// You may enable the other features individually like this:
// tr := zip.OpenReader("some.zip")
// tr.SetSecurityMode(tr.GetSecurityMode() | zip.SanitizeFileMode | zip.SkipSpecialFiles)
// or
// tr.SetSecurityMode(zip.MaximumSecurityMode)
//
// You may opt out from a certain feature like this:
// tr.SetSecurityMode(tr.GetSecurityMode() &^ zip.SanitizeFileMode)
package zip

import (
	"archive/zip" // NOLINT
	"io"
	"io/fs"
	"strings"

	"github.com/google/safearchive/sanitizer"
)

const (
	// Store no compression
	Store uint16 = zip.Store
	// Deflate DEFLATE compressed
	Deflate uint16 = zip.Deflate
)

var (
	// ErrFormat not a valid zip file
	ErrFormat = zip.ErrFormat
	// ErrAlgorithm unsupported compression algorithm
	ErrAlgorithm = zip.ErrAlgorithm
	// ErrChecksum checksum error
	ErrChecksum = zip.ErrChecksum
)

// A Compressor returns a new compressing writer, writing to w.
// The WriteCloser's Close method must be used to flush pending data to w.
// The Compressor itself must be safe to invoke from multiple goroutines
// simultaneously, but each returned writer will be used only by
// one goroutine at a time.
type Compressor = zip.Compressor

// A Decompressor returns a new decompressing reader, reading from r.
// The ReadCloser's Close method must be used to release associated resources.
// The Decompressor itself must be safe to invoke from multiple goroutines
// simultaneously, but each returned reader will be used only by
// one goroutine at a time.
type Decompressor = zip.Decompressor

// A File is a single file in a ZIP archive.
// The file information is in the embedded FileHeader.
// The file content can be accessed by calling Open.
type File = zip.File

// FileHeader describes a file within a zip file.
// See the zip spec for details.
type FileHeader = zip.FileHeader

// Note: we wrap the core ReadCloser/Reader structs so we can
// add the SetSecurityMode function that reapplies the security logic
// on the entries of the function.
// We chose this option to keep 100% signature compatibility with the core

// A ReadCloser is a Reader that must be closed when no longer needed.
type ReadCloser struct {
	Reader
	upstreamReadCloser *zip.ReadCloser
}

// A Reader serves content from a ZIP archive.
type Reader struct {
	*zip.Reader
	originalFiles []*zip.File
	securityMode  SecurityMode
}

// Writer implements a zip file writer.
type Writer = zip.Writer

// SecurityMode controls security features to enforce
type SecurityMode int

const (
	// PreventSymlinkTraversal security mode detects symlink
	PreventSymlinkTraversal SecurityMode = 1
	// SkipSpecialFiles security mode skips special files (e.g. block devices or fifos), links are allowed still
	SkipSpecialFiles SecurityMode = 2
	// SanitizeFileMode will drop special file modes (e.g. setuid and tmp bit)
	SanitizeFileMode SecurityMode = 4
	// SanitizeFilenames will sanitize filenames (dropping .. path components and turning entries into relative)
	SanitizeFilenames SecurityMode = 8
)

// DefaultSecurityMode enables path traversal security measures. This mode should be safe for all
// existing integrations.
const DefaultSecurityMode = SanitizeFilenames | PreventSymlinkTraversal

// MaximumSecurityMode enables all security features. Apps that care about file contents only
// and nothing unix specific (e.g. file modes or special devices) should use this mode.
const MaximumSecurityMode = DefaultSecurityMode | SanitizeFileMode | SkipSpecialFiles

func isSpecialFile(f zip.File) bool {
	amode := f.Mode()
	for _, m := range []fs.FileMode{fs.ModeDevice, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeCharDevice, fs.ModeIrregular} {
		if amode&fs.FileMode(m) != 0 {
			return true
		}
	}
	return false
}

// applyMagic sanitizes and/or filters the entries of this zip archive
// depending on the SecurityMode setting.
// See the SecurityMode constants above to learn more about what kind of
// security measures are currently supported.
func applyMagic(files []*zip.File, securityMode SecurityMode) []*zip.File {

	symlinks := map[string]bool{}
	var re []*zip.File
	for _, fp := range files {
		// making a copy, since we change some fields (Name and ExternalAttrs)
		f := *fp

		if securityMode&SanitizeFilenames != 0 {
			// Sanitize filename
			f.Name = sanitizer.SanitizePath(f.Name)
		}

		if securityMode&PreventSymlinkTraversal != 0 {
			fName := strings.TrimSuffix(f.Name, "/")
			n := strings.Split(fName, "/")
			traversal := false
			for i := 1; i <= len(n); i++ {
				subPath := strings.Join(n[0:i], "/")
				if symlinks[subPath] {
					// a symlink has already been seen on this path. We need to drop this entry.
					traversal = true
					break
				}
			}
			if traversal {
				continue
			}
			if f.Mode()&fs.ModeSymlink != 0 {
				symlinks[fName] = true
			}
		}

		if securityMode&SkipSpecialFiles != 0 {
			if isSpecialFile(f) {
				continue
			}
		}

		if securityMode&SanitizeFileMode != 0 {
			amode := f.Mode()
			for _, m := range []fs.FileMode{fs.ModeTemporary, fs.ModeAppend, fs.ModeExclusive, fs.ModeSetuid, fs.ModeSetgid, fs.ModeSticky} {
				amode = amode &^ fs.FileMode(m)
			}
			f.SetMode(amode)
		}

		re = append(re, &f)
	}

	return re
}

// OpenReader will open the Zip file specified by name and return a ReadCloser.
func OpenReader(name string) (*ReadCloser, error) {
	o, err := zip.OpenReader(name)
	if err != nil {
		return nil, err
	}

	//ReadCloser: o, originalFiles: o.File
	r := Reader{Reader: &o.Reader, originalFiles: o.File}
	rc := ReadCloser{Reader: r, upstreamReadCloser: o}
	rc.SetSecurityMode(DefaultSecurityMode)
	return &rc, nil
}

// SetSecurityMode applies the security rules on the set of files in the archive
func (r *ReadCloser) SetSecurityMode(sm SecurityMode) {
	r.File = applyMagic(r.originalFiles, sm)
	r.securityMode = sm
}

// GetSecurityMode returns the currently enabled security rules
func (r *ReadCloser) GetSecurityMode() SecurityMode {
	return r.securityMode
}

// Close closes the Zip file, rendering it unusable for I/O.
func (r *ReadCloser) Close() error {
	r.originalFiles = nil
	return r.upstreamReadCloser.Close()
}

// NewReader returns a new Reader reading from r, which is assumed to
// have the given size in bytes.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	o, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	re := Reader{Reader: o, originalFiles: o.File}
	re.SetSecurityMode(DefaultSecurityMode)
	return &re, nil
}

// SetSecurityMode applies the security rules on the set of files in the archive
func (r *Reader) SetSecurityMode(sm SecurityMode) {
	r.File = applyMagic(r.originalFiles, sm)
	r.securityMode = sm
}

// GetSecurityMode returns the currently enabled security rules
func (r *Reader) GetSecurityMode() SecurityMode {
	return r.securityMode
}

// FileInfoHeader creates a partially-populated FileHeader from an
// fs.FileInfo.
// Because fs.FileInfo's Name method returns only the base name of
// the file it describes, it may be necessary to modify the Name field
// of the returned header to provide the full path name of the file.
// If compression is desired, callers should set the FileHeader.Method
// field; it is unset by default.
func FileInfoHeader(fi fs.FileInfo) (*FileHeader, error) {
	return zip.FileInfoHeader(fi)
}

// RegisterDecompressor allows custom decompressors for a specified method ID.
// The common methods Store and Deflate are built in.
func RegisterDecompressor(method uint16, dcomp Decompressor) {
	zip.RegisterDecompressor(method, dcomp)
}

// RegisterCompressor registers custom compressors for a specified method ID.
// The common methods Store and Deflate are built in.
func RegisterCompressor(method uint16, comp Compressor) {
	zip.RegisterCompressor(method, comp)
}

// NewWriter returns a new Writer writing a zip file to w.
func NewWriter(w io.Writer) *Writer {
	return zip.NewWriter(w)
}
