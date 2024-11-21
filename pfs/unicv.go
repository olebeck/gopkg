package pfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

type sce_irodb_header_t struct {
	Magic     [8]byte
	Version   uint8
	BlockSize uint32
	Unk2      uint32
	Unk3      uint32
	DataSize  uint64
}

type sce_iftbl_header_t struct {
	Magic              [8]byte //SCEIFTBL
	Version            uint32  // this is probably version? value is always 2
	PageSize           uint32  //expected 0x400
	BinTreeNumMaxAvail uint32  // this is probably max number of sectors in a single sig_tbl_normal_t. expected value is 0x32
	NumSectors         uint32  //this shows how many sectors of data in total will follow this block. one sig_tbl_normal_t can contain 0x32 sectors at max
	//multiple sig_tbl_normal_t group into single file

	//This is sector size for files.db
	FileSectorSize uint32 // expected 0x8000

	Padding uint32 //this is probably padding? always zero

	//these records are empty if sce_iftbl_header_t corresponds to directory
	Data1  [20]byte
	Dbseed [20]byte // this is a base key that is used to derive tweak_enc_key - one of the keys required for decryption
}

type sce_icvdb_header_t struct {
	Magic          [8]byte //SCEICVDB
	Version        uint32  // this is probably version? value is always 2
	FileSectorSize uint32
	PageSize       uint32 //expected 0x400
	Root_page_idx  uint32 // index of the root page
	Unk0           uint32 //0xFFFFFFFF
	Unk1           uint32 //0xFFFFFFFF
	DataSize       uint64 // total size of all data pages; a multiple of pageSize
	NumSectors     uint32
	MerkleTreeRoot [20]byte
}

type sce_inull_header_t struct {
	Magic   [8]byte //SCEINULL
	Version uint32  // 1
	Unk1    uint32
	Unk2    uint32
	Unk3    uint32
}

type sig_tbl_header_t struct {
	BinTreeSize uint32 // for unicv.db for blocksize 0x400 this would be 0x3f8 = sizeof(sig_tbl_header_t) + (0x32 * 0x14) : which are maxNSectors * sigSize (0x8 bytes are unused)
	// for icv.db for blocksize 0x400 this would be 0x394 = sizeof(sig_icv_tbl_header_t) + (0x2D * 0x14) : which are 2D * sigSize (0x6C bytes are unused)
	SigSize       uint32 //expected 0x14 - size of hmac-sha1
	NumSignatures uint32 //number of chunks in this block
	Padding       uint32 //most likely padding ? always zero
}

type Unicv struct {
	Header sce_irodb_header_t
}

func ParseUnicv(r io.Reader) (*Unicv, error) {
	unicv := Unicv{}
	if err := binary.Read(r, binary.LittleEndian, &unicv.Header); err != nil {
		return nil, err
	}

	numBlocks := int(unicv.Header.DataSize / uint64(unicv.Header.BlockSize))
	for i := 0; i < numBlocks; i++ {
		var magic = make([]byte, 4)
		if _, err := io.ReadAtLeast(r, magic, 4); err != nil {
			return nil, err
		}
		switch string(magic) {
		case "SCEIFTBL": //SCEIFTBL (magic word) - sce interface file table (file record in unicv)
		case "SCEICVDB": //SCEICVDB (magic word) - sce interface C vector database (icv file corresponding to real file)
		case "SCEINULL": //SCEINULL (magic word) - sce interface NULL (icv file corresponding to real directory)
		default:
			return nil, fmt.Errorf("wrong magic %s", magic)
		}

		if err := binary.Read(r, binary.LittleEndian, &unicv.Header); err != nil {
			return nil, err
		}
	}

	return &unicv, nil
}
