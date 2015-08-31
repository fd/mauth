package server

import "text/template"

//go:generate go-bindata -pkg=server assets/

func mustParseTmpl(path string) *template.Template {
	src, err := Asset(path)
	if err != nil {
		panic(err)
	}
	return template.Must(template.New(path).Parse(string(src)))
}
