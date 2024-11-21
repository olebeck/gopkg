package pkg

import (
	"bytes"
	"fmt"
	"io"
)

type StreamReader struct {
	r          io.Reader
	readerRead int64
	buf        bytes.Buffer
}

func NewStreamReader(r io.Reader) *StreamReader {
	return &StreamReader{
		r: r,
	}
}

func (r *StreamReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}

	if r.readerRead < off {
		// skp
		io.CopyN(&r.buf, r.r, off-r.readerRead)
		r.readerRead = off
	}

	// if buffer already has some data
	if r.buf.Len()-int(off) > 0 {
		n = copy(p, r.buf.Bytes()[off:])
		p = p[n:]
		if len(p) == 0 {
			return
		}
	}

	po := p

read:
	n2, err := r.r.Read(p)
	r.readerRead += int64(n2)
	n += n2
	r.buf.Write(p[:n2])
	if err != nil {
		return n, err
	}
	if n < len(po) {
		p = p[n2:]
		goto read
	}
	return
}
