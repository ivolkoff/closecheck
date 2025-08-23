package main

import (
	"io"
	"net/http"
)

func doReq() *http.Response {
	res, err := http.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}

	return res
}

// External closer function
func CloseWithDefer(c io.Closer) { // want CloseWithDefer:"is closer"
	doClose(c)
}

func doClose(c io.Closer) { // want doClose:"is closer"
	c.Close()
}

func main() {
	res := doReq()

	CloseWithDefer(res.Body)
}
