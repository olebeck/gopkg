package pkg_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/olebeck/go-pkg"
)

func TestRead(t *testing.T) {
	//pa := "IP9100-PCSI00011_00-PSMRUNTIME000000.pkg"
	//pa := "dRICewDJtPZHtBCwPvyzdGdmGGVSLtvrJhEoxtJwhXYCFAVEUmOZaMCqmDyludGWPCrCJxIPINoaWQzBwVBJsnyulhZclhwSFdjnD.pkg"
	//pa := "LA-PN.VT.DE-STORE-0.pkg"
	//pa := "ZKlYCQbMrRogaHfKkPQRtoyOKOLDRsmQyZRgFkqMOkkxcyyPAeWxFGWbVjziCeZg.pkg"
	pa := "IV0000-ABCD12345_00-0123456789ABCDEF.pkg"
	f, err := os.Open(pa)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pkg.Read(f)
	if err != nil {
		t.Fatal(err)
	}

	name := pa[:len(pa)-len(path.Ext(pa))]

	for _, item := range p.Items {
		n := path.Join("out", name, item.Name)
		os.MkdirAll(path.Dir(n), 0777)
		if item.IsDir() {
			continue
		}
		f, err := os.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(f, item)
		f.Close()
	}
}

func TestNPS(t *testing.T) {
	games, err := pkg.GetGames()
	if err != nil {
		t.Fatal(err)
	}

	os.Mkdir("data", 0777)

	for _, game := range games {
		dataPath := "data/" + game.ContentID + ".json"
		fmt.Printf("%#+v\n", game)
		if game.PKG == "" || game.PKG == "MISSING" || game.PKG == "CART ONLY" || game.PKG == "NOT REQUIRED" {
			continue
		}
		if strings.Contains(game.PKG, "nopaystation.com") {
			continue
		}

		if _, err := os.Stat(dataPath); err == nil {
			continue
		}

		resp, err := http.Get(game.PKG)
		if err != nil {
			t.Fatal(err)
		}
		r := pkg.NewStreamReader(resp.Body)
		p, err := pkg.Read(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		{
			f, err := os.Create(dataPath)
			if err != nil {
				t.Fatal(err)
			}
			e := json.NewEncoder(f)
			e.SetIndent("", "  ")
			err = e.Encode(p)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
	}

}
