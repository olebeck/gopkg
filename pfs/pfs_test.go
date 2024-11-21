package pfs_test

import (
	"os"
	"testing"

	"github.com/olebeck/go-pkg/pfs"
)

func TestPFS(t *testing.T) {
	fs := os.DirFS("pfs_encrypted_test")
	p, err := pfs.NewPFS(fs)
	if err != nil {
		t.Fatal(err)
	}
	_ = p
}
