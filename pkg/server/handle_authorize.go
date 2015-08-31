package server

import (
	"fmt"
	"net/http"

	"github.com/RangelReale/osin"
)

func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	resp := s.oauthServer.NewResponse()
	defer resp.Close()

	if ar := s.oauthServer.HandleAuthorizeRequest(resp, r); ar != nil {

		if !s.handleLogin(ar, w, r) {
			return
		}

		ar.Authorized = true
		s.oauthServer.FinishAuthorizeRequest(resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		fmt.Printf("ERROR: %s\n", resp.InternalError)
	}
	// if !resp.IsError {
	// 	resp.Output["custom_parameter"] = 187723
	// }

	osin.OutputJSON(resp, w, r)
}
