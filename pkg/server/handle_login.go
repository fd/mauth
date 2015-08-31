package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/RangelReale/osin"
	"github.com/dgrijalva/jwt-go"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

var loginPageTmpl = mustParseTmpl("assets/login.html")

func (s *server) handleLogin(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {
	var (
		uid string
		err error
	)

	uid, err = s.handleFormAuth(w, r)
	if err == nil {
		s.writeCookie(w, uid)
		return true
	}
	if err != ErrInvalidCredentials {
		log.Printf("error: %s", err)
		s.clearCookie(w)
		return false
	}

	uid, err = s.handleCookieAuth(w, r)
	if err == nil {
		s.writeCookie(w, uid)
		return true
	}
	if err != ErrInvalidCredentials {
		log.Printf("error: %s", err)
		s.clearCookie(w)
		return false
	}

	s.clearCookie(w)
	params := url.Values{
		"response_type": {string(ar.Type)},
		"client_id":     {ar.Client.GetId()},
		"state":         {ar.State},
		"redirect_uri":  {ar.RedirectUri},
	}
	authorizeURL := "/authorize?" + params.Encode()

	loginPageTmpl.Execute(w, struct {
		ActionURL string
	}{
		ActionURL: authorizeURL,
	})

	return false
}

func (s *server) handleCookieAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie("u")
	if err == http.ErrNoCookie {
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", err
	}
	if cookie == nil {
		return "", ErrInvalidCredentials
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		id, _ := token.Header["kid"].(string)
		_, key, err := s.lookupKey(id)
		return key, err
	})
	if err == nil && token.Valid {
		uid, _ := token.Claims["uid"].(string)
		return uid, nil
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return "", ErrInvalidCredentials
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return "", ErrInvalidCredentials
		} else {
			return "", ErrInvalidCredentials
		}
	}

	if err != nil {
		return "", ErrInvalidCredentials
	}

	panic("not reachable")
}

func (s *server) handleFormAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.Method != "POST" {
		return "", nil
	}

	r.ParseForm()
	if r.Form.Get("email") == "test@mrhenry.be" && r.Form.Get("password") == "test" {
		return "test@mrhenry.be", nil
	}

	return "", ErrInvalidCredentials
}

func (s *server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "u",
		Path:   "/authorize",
		MaxAge: -1,
	})
}

func (s *server) writeCookie(w http.ResponseWriter, uid string) {
	id, key, err := s.lookupKey("")
	if err != nil {
		s.clearCookie(w)
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = id
	token.Claims["uid"] = uid
	token.Claims["exp"] = time.Now().Add(time.Hour * 24 * 7).Unix()
	tokenString, err := token.SignedString(key)
	if err != nil {
		s.clearCookie(w)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "u",
		Path:     "/authorize",
		MaxAge:   60 * 60 * 24 * 14,
		HttpOnly: true,
		Value:    tokenString,
	})
}
