package server

import (
	"fmt"
	"net/http"

	"github.com/RangelReale/osin"
)

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	resp := s.oauthServer.NewResponse()
	defer resp.Close()

	if ar := s.oauthServer.HandleAccessRequest(resp, r); ar != nil {
		switch ar.Type {

		case osin.AUTHORIZATION_CODE:
			ar.Authorized = true

		case osin.REFRESH_TOKEN:
			ar.Authorized = true

		case osin.PASSWORD:
			if ar.Username == "test" && ar.Password == "test" {
				ar.Authorized = true
			}

		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true

		}
		s.oauthServer.FinishAccessRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	// if !resp.IsError {
	// 	resp.Output["custom_parameter"] = 19923
	// }

	osin.OutputJSON(resp, w, r)
}
