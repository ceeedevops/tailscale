// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
)

// HashBlockSize is the size of blocks that [HashPartialFile] uses
// to hash a partial file.
const HashBlockSize = 64 << 10

// ClientID is an opaque identifier for file resumption.
// A client can only list and resume partial files for its own ID.
type ClientID string // e.g., "n12345CNTRL"

func (id ClientID) partialSuffix() string {
	return "." + string(id) + partialSuffix // e.g., ".n12345CNTRL.partial"
}

// PartialFiles returns a list of partial files in [Handler.Dir]
// that were sent (or is actively being sent) by the provided id.
func (s *Handler) PartialFiles(id ClientID) (ret []string, err error) {
	if s.Dir == "" {
		return ret, errNoTaildrop
	}

	f, err := os.Open(s.Dir)
	if err != nil {
		return ret, err
	}
	defer f.Close()

	suffix := id.partialSuffix()
	for {
		des, err := f.ReadDir(10)
		if err != nil {
			return ret, err
		}
		for _, de := range des {
			if name := de.Name(); strings.HasSuffix(name, suffix) {
				ret = append(ret, name)
			}
		}
		if err == io.EOF {
			return ret, nil
		}
	}
}

// HashPartialFile hashes the contents of a partial file sent by id,
// starting at the specified offset and for the specified length.
// It hashes in blocks of size [HashBlockSize] and
// reports the length of the last block, which may be less than [HashBlockSize].
func (s *Handler) HashPartialFile(id ClientID, baseName string, offset, length int64) (hashes [][sha256.Size]byte, lastBlockLen int, err error) {
	if s.Dir == "" {
		return nil, 0, errNoTaildrop
	}

	dstFile, ok := s.joinDir(baseName + id.partialSuffix())
	if !ok {
		return nil, 0, errors.New("invalid base name")
	}
	f, err := os.Open(dstFile)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	b := make([]byte, 0, HashBlockSize)
	r := io.LimitReader(f, length)
	for {
		switch n, err := io.ReadFull(r, b[:cap(b)]); {
		case err != nil && err != io.EOF && err != io.ErrUnexpectedEOF:
			return hashes, lastBlockLen, err
		case n == 0:
			return hashes, len(b), nil
		default:
			b = b[:n]
			h.Reset()
			h.Write(b)
			hashes = append(hashes, [sha256.Size]byte(h.Sum(nil)))
		}
	}
}
