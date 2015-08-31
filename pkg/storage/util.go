package storage

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

func randomBase64(n int) string {
	buf := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic("rand.Reader failed")
	}

	return base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)
}
