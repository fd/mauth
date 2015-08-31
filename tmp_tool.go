package main

import (
	"net/http"
	"os"

	"github.com/fd/mauth/pkg/server"
	"github.com/fd/mauth/pkg/storage"
)

func main() {
	storage, err := storage.Open(os.Getenv("MONGO_URL"))
	if err != nil {
		panic(err)
	}

	defer storage.Close()

	http.ListenAndServe(":3000", server.New(storage))
}
