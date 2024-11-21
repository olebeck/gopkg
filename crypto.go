package pkg

import (
	"crypto/cipher"
	"errors"
	"io"
)

type ctrReader struct {
	reader  io.ReadSeeker
	block   cipher.Block
	stream  cipher.Stream
	ivStart []byte
	buffer  []byte
	offset  int64
}

func newCTR(reader io.ReadSeeker, block cipher.Block, iv []byte) *ctrReader {
	return &ctrReader{
		reader:  reader,
		block:   block,
		ivStart: iv,
		buffer:  make([]byte, block.BlockSize()),
	}
}

func (r *ctrReader) Seek(offset int64, whence int) (int64, error) {
	var absOffset int64
	switch whence {
	case io.SeekStart:
		absOffset = offset
	case io.SeekCurrent:
		absOffset = r.offset + offset
	case io.SeekEnd:
		fileSize, err := r.reader.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, err
		}
		absOffset = fileSize + offset
	default:
		return 0, errors.New("invalid whence")
	}

	if absOffset < 0 {
		return 0, errors.New("negative seek")
	}
	r.reader.Seek(absOffset, io.SeekStart)

	blockOffset := absOffset / int64(len(r.ivStart))
	var iv = make([]byte, len(r.ivStart))
	copy(iv, r.ivStart)
	incrementCounter(iv, int(blockOffset))

	r.stream = cipher.NewCTR(r.block, iv)
	return absOffset, nil
}

func (r *ctrReader) Read(data []byte) (int, error) {
	if r.stream == nil {
		r.stream = cipher.NewCTR(r.block, r.ivStart)
		r.reader.Seek(0, io.SeekStart)
	}

	n, err := r.reader.Read(data)
	if n > 0 {
		r.stream.XORKeyStream(data, data)
	}
	return n, err
}

func incrementCounter(counter []byte, increments int) {
	carry := uint32(increments)
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		val := uint32(counter[i]) + carry
		counter[i] = byte(val)
		carry = val >> 8 // Carry over to the next byte
	}
}
