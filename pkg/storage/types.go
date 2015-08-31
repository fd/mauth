package storage

import (
	"time"

	"gopkg.in/mgo.v2/bson"
)

type authorizeData struct {
	ClientID    bson.ObjectId
	Code        string
	State       string
	Scope       string
	RedirectUri string
	Created     time.Time
	ExpiresIn   int32
}

type accessData struct {
	ID           bson.ObjectId `json:"_id"`
	ClientID     bson.ObjectId
	AccessToken  string
	RefreshToken string
	Scope        string
	RedirectUri  string
	CreatedAt    time.Time
	ExpiresIn    int32
}
