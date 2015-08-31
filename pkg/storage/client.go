package storage

import "gopkg.in/mgo.v2/bson"

// Client is a oauth client
type Client struct {
	ID          bson.ObjectId `bson:"_id"`
	Name        string
	Secret      string
	RedirectUri string
}

// GetId : Client id
func (c *Client) GetId() string {
	return c.ID.Hex()
}

// GetSecret : Client secret
func (c *Client) GetSecret() string {
	return c.Secret
}

// GetRedirectUri : Base client uri
func (c *Client) GetRedirectUri() string {
	return c.RedirectUri
}

// GetUserData : Data to be passed to storage. Not used by the library.
func (c *Client) GetUserData() interface{} {
	return c
}
