package storage

import (
	"github.com/RangelReale/osin"
	"github.com/juju/errgo"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Storage struct {
	session    *mgo.Session
	db         *mgo.Database
	clients    *mgo.Collection
	authData   *mgo.Collection
	accessData *mgo.Collection
}

func Open(url string) (*Storage, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	db := session.DB("")

	storage := &Storage{
		session:    session,
		db:         db,
		clients:    db.C("clients"),
		authData:   db.C("authData"),
		accessData: db.C("accessData"),
	}

	storage.authData.EnsureIndexKey("code")
	storage.accessData.EnsureIndexKey("accesstoken")
	storage.accessData.EnsureIndexKey("refreshtoken")

	return storage, nil
}

// Clone the storage if needed. For example, using mgo, you can clone the session with session.Clone
// to avoid concurrent access problems.
// This is to avoid cloning the connection at each method access.
// Can return itself if not a problem.
func (s *Storage) Clone() osin.Storage {
	session := s.session.Clone()

	db := session.DB("")

	return &Storage{
		session:    session,
		db:         db,
		clients:    db.C("clients"),
		authData:   db.C("authData"),
		accessData: db.C("accessData"),
	}
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
	s.session.Close()
}

func (s *Storage) EnsureClient(id, name, redirectUri string) error {
	c, err := s.GetClient(id)
	if err != nil {
		return err
	}
	if c != nil {
		return nil
	}

	client := Client{
		ID:          bson.ObjectIdHex(id),
		Name:        name,
		Secret:      randomBase64(256),
		RedirectUri: redirectUri,
	}

	err = s.clients.Insert(&client)
	if err != nil {
		return errgo.Mask(err)
	}

	return nil
}

func (s *Storage) CreateClient(name, redirectUri string) (string, error) {
	client := Client{
		ID:          bson.NewObjectId(),
		Name:        name,
		Secret:      randomBase64(256),
		RedirectUri: redirectUri,
	}

	err := s.clients.Insert(&client)
	if err != nil {
		return "", errgo.Mask(err)
	}

	return client.ID.Hex(), nil
}

// GetClient loads the client by id (client_id)
func (s *Storage) GetClient(id string) (osin.Client, error) {
	if id == "" {
		return nil, nil
	}

	var (
		mid    = bson.ObjectIdHex(id)
		client *Client
	)

	err := s.clients.FindId(mid).One(&client)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return client, nil
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(d *osin.AuthorizeData) error {
	data := authorizeData{
		ClientID:    d.Client.GetUserData().(*Client).ID,
		Code:        d.Code,
		Created:     d.CreatedAt,
		ExpiresIn:   d.ExpiresIn,
		Scope:       d.Scope,
		RedirectUri: d.RedirectUri,
		State:       d.State,
	}

	err := s.authData.Insert(&data)
	if err != nil {
		return errgo.Mask(err)
	}

	return nil
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	var (
		mdata  authorizeData
		client *Client
	)

	err := s.authData.Find(bson.M{"code": code}).One(&mdata)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	err = s.clients.FindId(mdata.ClientID).One(&client)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	data := &osin.AuthorizeData{
		Client:      client,
		Code:        mdata.Code,
		ExpiresIn:   mdata.ExpiresIn,
		Scope:       mdata.Scope,
		RedirectUri: mdata.RedirectUri,
		State:       mdata.State,
		CreatedAt:   mdata.Created,
	}

	return data, nil
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) error {
	_, err := s.authData.RemoveAll(bson.M{"code": code})
	if err != nil {
		return errgo.Mask(err)
	}

	return nil
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *Storage) SaveAccess(d *osin.AccessData) error {
	data := &accessData{
		ID:           bson.NewObjectId(),
		ClientID:     d.Client.GetUserData().(*Client).ID,
		AccessToken:  d.AccessToken,
		RefreshToken: d.RefreshToken,
		Scope:        d.Scope,
		RedirectUri:  d.RedirectUri,
		CreatedAt:    d.CreatedAt,
		ExpiresIn:    d.ExpiresIn,
	}

	err := s.accessData.Insert(&data)
	if err != nil {
		return errgo.Mask(err)
	}

	d.UserData = data
	return nil
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	var (
		data   *accessData
		client *Client
	)

	err := s.accessData.Find(bson.M{"accesstoken": token}).One(&data)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	err = s.clients.FindId(data.ClientID).One(&client)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	d := &osin.AccessData{
		Client:       client,
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		Scope:        data.Scope,
		RedirectUri:  data.RedirectUri,
		CreatedAt:    data.CreatedAt,
		ExpiresIn:    data.ExpiresIn,
		UserData:     data,
	}

	return d, nil
}

// RemoveAccess revokes or deletes an AccessData.
func (s *Storage) RemoveAccess(token string) error {
	_, err := s.accessData.RemoveAll(bson.M{"accesstoken": token})
	if err != nil {
		return errgo.Mask(err)
	}

	return nil
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	if token == "" {
		return nil, nil
	}

	var (
		data   *accessData
		client *Client
	)

	err := s.accessData.Find(bson.M{"refreshtoken": token}).One(&data)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	err = s.clients.FindId(data.ClientID).One(&client)
	if err == mgo.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, errgo.Mask(err)
	}

	d := &osin.AccessData{
		Client:       client,
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		Scope:        data.Scope,
		RedirectUri:  data.RedirectUri,
		CreatedAt:    data.CreatedAt,
		ExpiresIn:    data.ExpiresIn,
		UserData:     data,
	}

	return d, nil
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *Storage) RemoveRefresh(token string) error {
	if token == "" {
		return nil
	}

	_, err := s.accessData.UpdateAll(bson.M{"refreshtoken": token}, bson.M{"$set": bson.M{"refreshtoken": ""}})
	if err != nil {
		return errgo.Mask(err)
	}

	return nil
}
