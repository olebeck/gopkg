package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	PKG_TYPE_VITA_APP = iota + 1
	PKG_TYPE_VITA_DLC
	PKG_TYPE_VITA_PATCH
	PKG_TYPE_VITA_PSM
	PKG_TYPE_PSP
	PKG_TYPE_PSX
	PKG_TYPE_VITA_LIVEAREA
)

func mustAes(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

var key_pkg_ps3_key = []byte{0x2e, 0x7b, 0x71, 0xd7, 0xc9, 0xc9, 0xa1, 0x4e, 0xa3, 0x22, 0x1f, 0x18, 0x88, 0x28, 0xb8, 0xf8}
var key_pkg_psp_key = []byte{0x07, 0xf2, 0xc6, 0x82, 0x90, 0xb5, 0x0d, 0x2c, 0x33, 0x81, 0x8d, 0x70, 0x9b, 0x60, 0xe6, 0x2b}
var key_pkg_vita_2 = mustAes([]byte{0xe3, 0x1a, 0x70, 0xc9, 0xce, 0x1d, 0xd7, 0x2b, 0xf3, 0xc0, 0x62, 0x29, 0x63, 0xf2, 0xec, 0xcb})
var key_pkg_vita_3 = mustAes([]byte{0x42, 0x3a, 0xca, 0x3a, 0x2b, 0xd5, 0x64, 0x9f, 0x96, 0x86, 0xab, 0xad, 0x6f, 0xd8, 0x80, 0x1f})
var key_pkg_vita_4 = mustAes([]byte{0xaf, 0x07, 0xfd, 0x59, 0x65, 0x25, 0x27, 0xba, 0xf1, 0x33, 0x89, 0x66, 0x8b, 0x17, 0xd9, 0xea})

type Pkg struct {
	Magic     [4]byte
	Revision  uint16
	Type      uint16
	ContentID string

	ContentType uint32
	Sfo         *Sfo
	Items       []Item
}

type Sfo struct {
}

type Item struct {
	Name          string
	Flags         int
	Size          int
	io.ReadSeeker `json:"-"`
}

func (p *Item) IsDir() bool {
	return p.Flags == 4
}

func (p *Item) String() string {
	return p.Name
}

func Read(r io.ReaderAt) (*Pkg, error) {
	p := &Pkg{}

	const headerSize = 232
	var header = make([]byte, headerSize)
	_, err := r.ReadAt(header, 0)
	if err != nil {
		return nil, err
	}

	copy(p.Magic[:], header[0:4])
	p.Revision = binary.BigEndian.Uint16(header[4:6])
	p.Type = binary.BigEndian.Uint16(header[6:8])

	metaOffset := binary.BigEndian.Uint32(header[8:12])
	metaCount := binary.BigEndian.Uint32(header[12:16])
	metaSize := binary.BigEndian.Uint32(header[16:20])

	itemCount := binary.BigEndian.Uint32(header[20:24])
	totalSize := binary.BigEndian.Uint64(header[24:32])
	encryptedOffset := binary.BigEndian.Uint64(header[32:40])
	encryptedSize := binary.BigEndian.Uint64(header[40:48])
	_ = totalSize
	_ = encryptedSize

	p.ContentID = string(header[48 : 48+0x24])

	digest := header[96:112]
	iv := header[112:128]
	keyType := header[231] & 7
	_ = digest

	var meta = make([]byte, metaSize)
	_, err = r.ReadAt(meta, int64(metaOffset))
	if err != nil {
		return nil, err
	}

	var itemOffset, itemSize uint32
	var sfoOffset, sfoSize uint32

	off := 0
	for i := 0; i < int(metaCount); i++ {
		m := meta[off:]
		metaElementType := binary.BigEndian.Uint32(m[0:4])
		metaElementSize := binary.BigEndian.Uint32(m[4:8])
		switch metaElementType {
		case 2:
			p.ContentType = binary.BigEndian.Uint32(m[8:12])
		case 13:
			itemOffset = binary.BigEndian.Uint32(m[8:12])
			itemSize = binary.BigEndian.Uint32(m[12:16])
		case 14:
			sfoOffset = binary.BigEndian.Uint32(m[8:12])
			sfoSize = binary.BigEndian.Uint32(m[12:16])
		default:
		}
		off += int(metaElementSize + 8)
	}
	_ = itemSize
	_ = sfoOffset
	_ = sfoSize

	var pkgType uint32
	switch p.ContentType {
	case 6:
		pkgType = PKG_TYPE_PSX
	case 7, 0xe, 0xf:
		pkgType = PKG_TYPE_PSP
	case 0x15:
		pkgType = PKG_TYPE_VITA_APP
	case 0x16:
		pkgType = PKG_TYPE_VITA_DLC
	case 0x18, 0x1d:
		pkgType = PKG_TYPE_VITA_PSM
	case 23:
		pkgType = PKG_TYPE_VITA_LIVEAREA
	default:
		return nil, fmt.Errorf("unknown ContentType %d", p.ContentType)
	}
	_ = pkgType

	var mainKey = make([]byte, 0x10)
	var ps3Cipher cipher.Block
	switch keyType {
	case 1:
		mainKey = key_pkg_psp_key
		ps3Cipher, err = aes.NewCipher(key_pkg_ps3_key)
		if err != nil {
			return nil, err
		}
	case 2:
		key_pkg_vita_2.Encrypt(mainKey, iv)
	case 3:
		key_pkg_vita_3.Encrypt(mainKey, iv)
	case 4:
		key_pkg_vita_4.Encrypt(mainKey, iv)
	default:
		return nil, errors.New("unknown key type")
	}
	mainCipher, err := aes.NewCipher(mainKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("iv:  %s\n", hex.EncodeToString(iv))
	fmt.Printf("key: %s\n", hex.EncodeToString(mainKey))

	// decrypted reader for the encrypted section
	rd := newCTR(io.NewSectionReader(r, int64(encryptedOffset), int64(encryptedSize)), mainCipher, iv)

	var itemData = make([]byte, itemSize)
	rd.Seek(int64(itemOffset), io.SeekStart)
	_, err = rd.Read(itemData)
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(itemCount); i++ {
		off := int64(32 * i)
		var item Item

		nameOffset := binary.BigEndian.Uint32(itemData[off:])
		nameSize := binary.BigEndian.Uint32(itemData[off+4:])
		dataOffset := binary.BigEndian.Uint64(itemData[off+8:])
		dataSize := binary.BigEndian.Uint64(itemData[off+16:])

		item.Size = int(dataSize)
		if nameSize > 0xffff {
			panic("aaaa") // broken decrypt, crash here to avoid allocating a billion bytes
		}

		extra := itemData[off+24 : off+32]
		item.Flags = int(extra[3])
		pspType := extra[0]

		item.Name = string(itemData[nameOffset : nameOffset+nameSize])

		var itemCipher = mainCipher
		if pkgType == PKG_TYPE_PSP || pkgType == PKG_TYPE_PSX && pspType == 0x90 {
			itemCipher = ps3Cipher
		}

		var itemIv = make([]byte, 0x10)
		copy(itemIv, iv)
		incrementCounter(itemIv, int(dataOffset/16))
		item.ReadSeeker = newCTR(io.NewSectionReader(r, int64(encryptedOffset+uint64(dataOffset)), int64(dataSize)), itemCipher, itemIv)

		p.Items = append(p.Items, item)
	}

	return p, nil
}
