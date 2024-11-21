package pfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"slices"
)

const filesdbMagic = "SCENGPFS"

type sce_ng_pfs_header_t struct {
	Magic                [8]byte
	Version              uint32
	Image_spec           uint16 // allows to distinguish unicv.db and icv.db - check is_unicv_to_img_type
	Key_id               uint16
	PageSize             uint32
	Bt_order             uint32     // order value of the binary tree - derived from btree_order
	Root_icv_page_number uint32     // derived from off2pgn or btree_top
	Files_salt           uint32     // first salt value used for key derrivation
	Unk6                 uint64     // is 0xFFFFFFFFFFFFFFFF
	TailSize             uint64     // size of data after this header
	Total_sz             uint64     // is 0
	Root_icv             [0x14]byte // 0x38 hmac-sha1 of (pageSize - 4) of page (pointed by root_icv_page_number) with secret derived from klicensee
	Header_icv           [0x14]byte // 0x4C hmac-sha1 of 0x16 bytes of header with secret derived from klicensee
	Rsa_sig0             [0x100]byte
	Rsa_sig1             [0x100]byte
	Padding              [0x1A0]byte
}

type sce_ng_pfs_block_header_t struct {
	Parent_page_number uint32
	Type               uint32
	NumFiles           uint32
	Padding            uint32
}

type sce_ng_pfs_file_header_t struct {
	Index    uint32 //parent index
	FileName [68]byte
}

type sce_ng_pfs_file_info_t struct {
	Index uint32
	Type  uint16
	Pad1  uint16
	Size  uint32
	Pad2  uint32
}

type sce_ng_pfs_block_t struct {
	Header      sce_ng_pfs_block_header_t
	FileHeaders [9]sce_ng_pfs_file_header_t
	FileInfos   [10]sce_ng_pfs_file_info_t
	FileHashes  [10][20]byte
}

type page_icv_data struct {
	Offset int64
	Page   uint32
	Icv    [0x14]byte
}

type FilesDB struct {
	Header   sce_ng_pfs_header_t
	Blocks   []sce_ng_pfs_block_t
	PageIcvs map[uint32][]page_icv_data
}

func ParseFilesDB(r io.Reader, klicensee, klicenseeDeriv []byte) (*FilesDB, error) {
	var filesDB FilesDB
	if err := binary.Read(r, binary.LittleEndian, &filesDB.Header); err != nil {
		return nil, err
	}
	filesDB.PageIcvs = make(map[uint32][]page_icv_data)

	secret := get_secret(klicensee, klicenseeDeriv, filesDB.Header.Files_salt, CRYPTO_ENGINE_CRYPTO_USE_KEYGEN, 0, 0)

	blockCount := filesDB.Header.TailSize / uint64(filesDB.Header.PageSize)
	var raw_block = bytes.NewBuffer(make([]byte, 1024))
	for page := 0; page < int(blockCount); page++ {
		raw_block.Reset()
		var block sce_ng_pfs_block_t
		if err := binary.Read(io.TeeReader(r, raw_block), binary.LittleEndian, &block); err != nil {
			return nil, err
		}

		icv := page_icv_data{
			Offset: 0,
			Page:   uint32(page),
		}

		icvValue := calculate_node_icv(&filesDB.Header, secret, &block.Header, raw_block.Bytes())
		icv.Icv = [20]byte(icvValue)
		filesDB.Blocks = append(filesDB.Blocks, block)
		filesDB.PageIcvs[block.Header.Parent_page_number] = append(filesDB.PageIcvs[block.Header.Parent_page_number], icv)
	}

	if !validate_hash_tree(0, filesDB.Header.Root_icv_page_number, &filesDB) {
		panic("invalid hash tree")
	}

	return &filesDB, nil
}

func validate_hash_tree(level int, page uint32, fdb *FilesDB) bool {
	block := &fdb.Blocks[page]

	icvs := fdb.PageIcvs[page]
	for _, icv := range icvs {
		if slices.Contains(block.FileHashes[:], icv.Icv) {
			// OK
			if !validate_hash_tree(level+1, icv.Page, fdb) {
				return false
			}
			continue
		}
		return false
	}
	return true
}

const CRYPTO_ENGINE_CRYPTO_USE_KEYGEN = 2
const CRYPTO_ENGINE_CRYPTO_USE_CMAC = 1

const (
	img_type_gamedata = 0
	img_type_savedata = 1
	img_type_ac_root  = 2 // ADDCONT
	img_type_acid_dir = 3 // DLC
)

var img_spec_to_img_type = map[uint16]uint16{
	1: img_type_gamedata,
	2: img_type_savedata,
	3: img_type_ac_root,
	4: img_type_acid_dir,
}

func img_spec_to_crypto_engine_flag(image_spec uint16) uint32 {
	img_type, ok := img_spec_to_img_type[image_spec]
	if !ok {
		panic("invalid image spec")
	}

	switch img_type {
	case img_type_gamedata: //gamedata is considered to be a pfs_pack (unicv.db - sef of pfs_file objects)
		return CRYPTO_ENGINE_CRYPTO_USE_KEYGEN
	case img_type_savedata: //savedata is considered to be a pfs_file (icv.db)
		return 0
	case img_type_ac_root: //ADDCONT is considered to be a pfs_file (icv.db)
		return 0
	case img_type_acid_dir:
		return CRYPTO_ENGINE_CRYPTO_USE_KEYGEN //DLCs are considered to be a pfs_pack (unicv.db - sef of pfs_file objects)
	default:
		return CRYPTO_ENGINE_CRYPTO_USE_CMAC
	}
}

func get_secret(klicensee, klicenseeDeriv []byte, files_salt, crypto_engine_flag, icv_salt uint32, key_id uint16) []byte {
	if crypto_engine_flag&CRYPTO_ENGINE_CRYPTO_USE_KEYGEN != 0 {
		return generate_secret_np(klicenseeDeriv, files_salt, icv_salt, key_id)
	}
	return generate_secret(klicensee, icv_salt)
}

func generate_secret_np(klicenseeDeriv []byte, files_salt, icv_salt uint32, key_id uint16) []byte {
	var saltin []byte
	if files_salt != 0 {
		saltin = binary.LittleEndian.AppendUint32(saltin, files_salt)
	}
	saltin = binary.LittleEndian.AppendUint32(saltin, icv_salt)
	h := hmac.New(sha1.New, hmac_key1)
	h.Write(saltin)
	combo := h.Sum(nil)

	return AESCBCEncryptWithKeygen_base(klicenseeDeriv, iv0, combo, key_id)
}

func generate_secret(klicensee []byte, icv_salt uint32) []byte {
	base0 := sha1.Sum(klicensee)
	saltin := binary.LittleEndian.AppendUint32([]byte{0, 0, 0, 0xA}, icv_salt)
	base1 := sha1.Sum(saltin)
	drvKey := sha1.Sum(append(base0[:], base1[:]...))
	return drvKey[:]
}

func node_size(index uint32) uint32 {
	return 0x6C*index - 0x38
}

func order_max_avail(pagesize uint32) uint32 {
	//calculate max possible index until data size does not fit the page
	var index uint32 = 1
	for pagesize > node_size(index) {
		index++
	}

	//substract one entry if last entry overflows the page
	if pagesize < node_size(index) {
		index--
	}
	return index
}

func c_node_icvs(raw_data []byte, order uint32) []byte {
	offset := 0x48*order + 0x10*order - 0x38
	return raw_data[offset:]
}

func calculate_node_icv(ngh *sce_ng_pfs_header_t, secret []byte, node_header *sce_ng_pfs_block_header_t, raw_data []byte) []byte {
	order := order_max_avail(ngh.PageSize)
	if ngh.Version == 5 {
		dataSize := (0x6C*order - 0x3C)
		h := hmac.New(sha1.New, secret)
		h.Write(raw_data[4 : 4+dataSize])
		return h.Sum(nil)
	}

	nEntries := node_header.NumFiles
	if node_header.Type > 0 {
		nEntries++
	}

	icvs_base := c_node_icvs(raw_data, order)

	icv := make([]byte, 0x14)
	for i := 0; i < int(nEntries); i++ {
		icv_contract_hmac(icv, secret, icv, icvs_base[i*0x14:(i+1)*0x14])
	}
	return icv
}

func icv_contract_hmac(iv, key, base0, base1 []byte) {
	h := hmac.New(sha1.New, key)
	h.Write(base0)
	h.Write(base1)
	h.Sum(iv[:0])
}

func AESCBCEncryptWithKeygen_base(key, tweak, src []byte, key_id uint16) []byte {
	size_tail := len(src) & 0xF     // get size of tail
	size_block := len(src) & (^0xF) // get block size aligned to 0x10 boundary

	//encrypt N blocks of source data with klicensee and iv
	dst := make([]byte, len(src))
	ciph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if size_block != 0 {
		cipher.NewCBCEncrypter(ciph, tweak).CryptBlocks(dst, src[:size_block])
	}

	//handle tail section - do a Cipher Text Stealing

	if size_tail == 0 {
		return dst
	}

	//align destination buffer

	var tweak_enc = make([]byte, 0x10)

	//encrypt iv using klicensee
	tweak = dst[size_block-16 : size_block]

	ciph.Encrypt(tweak_enc, tweak)

	//produce destination tail by xoring source tail with encrypted iv

	for i := 0; i < size_tail; i++ {
		dst[size_block+i] = src[size_block+i] ^ tweak_enc[i]
	}

	return dst
}

var contract_key0, _ = aes.NewCipher([]byte{0xE1, 0x22, 0x13, 0xB4, 0x80, 0x16, 0xB0, 0xE9, 0x9A, 0xB8, 0x1F, 0x8E, 0xC0, 0x2A, 0xD4, 0xA2})

func kprx_auth_service_0x50001(klicensee []byte) []byte {
	var derived = make([]byte, len(klicensee))
	contract_key0.Decrypt(derived, klicensee)
	return derived
}
