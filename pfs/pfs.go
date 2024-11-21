package pfs

import (
	"io/fs"
)

type PFS struct {
	fs fs.FS

	Unicv   *Unicv
	FilesDB *FilesDB
}

func NewPFS(fs fs.FS) (*PFS, error) {
	p := &PFS{
		fs: fs,
	}
	err := p.init()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PFS) init() (err error) {
	f, err := p.fs.Open("sce_pfs/files.db")
	if err != nil {
		return err
	}

	klicensee := []byte{
		0xEF, 0x3E, 0x79, 0x08, 0x49, 0x41, 0x27, 0xAE, 0x52, 0xA8, 0xEB, 0xC0, 0x30, 0xF2, 0x00, 0x7C,
	}

	klicenseeDeriv := kprx_auth_service_0x50001(klicensee)

	p.FilesDB, err = ParseFilesDB(f, klicensee, klicenseeDeriv)
	if err != nil {
		return err
	}
	return nil
}

func (*PFS) Open(name string) (fs.File, error) {
	return nil, nil
}
