package server

import (
	"net/http"

	"golang.org/x/oauth2"
)

var profilePageTmpl = mustParseTmpl("assets/profile.html")

func (s *server) handleProfile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("s")
	if err != nil || cookie == nil {
		client, err := s.store.GetClient("55e42e87b4301941f9000002")
		if err != nil {
			panic(err)
		}

		conf := &oauth2.Config{
			ClientID:     client.GetId(),
			ClientSecret: client.GetSecret(),

			Scopes: []string{
				"mauth:profile:read",
				"mauth:profile:write",
			},

			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://127.0.0.1:3000/authorize",
				TokenURL: "http://127.0.0.1:3000/token",
			},
		}

		if code := r.FormValue("code"); code != "" {
			// TODO validate state

			tok, err := conf.Exchange(oauth2.NoContext, code)
			if err != nil {
				panic(err)
			}
			if !tok.Valid() {
				url := conf.AuthCodeURL("state", oauth2.AccessTypeOnline)
				http.Redirect(w, r, url, http.StatusMovedPermanently)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:   "s",
				Path:   "/me",
				MaxAge: 60 * 60,
			})
			http.Redirect(w, r, "/me", http.StatusMovedPermanently)
			return
		} else {
			url := conf.AuthCodeURL("state", oauth2.AccessTypeOnline)
			http.Redirect(w, r, url, http.StatusMovedPermanently)
			return
		}
	}

	profilePageTmpl.Execute(w, struct {
		ActionURL string
	}{})

}
