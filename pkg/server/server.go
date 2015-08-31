package server

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/RangelReale/osin"

	"github.com/fd/mauth/pkg/storage"
)

type server struct {
	store       *storage.Storage
	oauthServer *osin.Server
	defaultKey  string
	keys        map[string]*rsa.PrivateKey
}

// New oauth server
func New(store *storage.Storage) http.Handler {
	conf := osin.NewServerConfig()

	conf.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{
		osin.CODE,
		osin.TOKEN}

	conf.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN,
		osin.PASSWORD,
		osin.CLIENT_CREDENTIALS}

	conf.AllowGetAccessRequest = true
	conf.RedirectUriSeparator = " "

	oauthServer := osin.NewServer(conf, store)

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	err = store.EnsureClient("55e42e87b4301941f9000002", "Profile Page", "http://localhost:3000/me")
	if err != nil {
		panic(err)
	}

	return &server{
		store:       store,
		oauthServer: oauthServer,
		defaultKey:  "1",
		keys:        map[string]*rsa.PrivateKey{"1": key},
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {

	case "/authorize":
		s.handleAuthorize(w, r)

	case "/token":
		s.handleToken(w, r)

	case "/me":
		s.handleProfile(w, r)

	default:
		http.NotFound(w, r)

	}
}

func (s *server) lookupKey(id string) (string, *rsa.PrivateKey, error) {
	if id == "" {
		id = s.defaultKey
	}

	key := s.keys[id]
	if key == nil {
		return "", nil, ErrInvalidCredentials
	}

	return id, key, nil
}
