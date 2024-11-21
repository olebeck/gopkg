package pkg

import (
	"encoding/csv"
	"io"
	"net/http"
)

type Game struct {
	TitleID   string
	Name      string
	PKG       string
	ZRIF      string
	ContentID string
}

func GetGames() ([]Game, error) {
	resp, err := http.Get("https://nopaystation.com/tsv/PSV_GAMES.tsv")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	cr := csv.NewReader(resp.Body)
	cr.Comma = '\t'
	cr.Read()

	var games []Game
	for {
		records, err := cr.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		var game Game
		game.TitleID = records[0]
		game.Name = records[2]
		game.PKG = records[3]
		game.ZRIF = records[4]
		game.ContentID = records[5]
		games = append(games, game)
	}
	return games, nil
}
