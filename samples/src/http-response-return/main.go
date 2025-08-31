package main

import (
	"io"
	"net/http"
)

func doReq() io.ReadCloser {
	res, err := http.Get("https://www.google.com")
	if err != nil {
		panic(err)
	}

	return res.Body
}

func doReq2() *http.Response {
	res, _ := http.Get("https://www.google.com")

	return aCloser.doNothing(res)
}

type closer struct {
}

func (c closer) closeBody(bodyToBeClosed io.Closer) { // want closeBody:"is closer"
	_ = bodyToBeClosed.Close()
}

func (c closer) doNothing(res *http.Response) *http.Response { // want doNothing:"is not closer"
	return res
}

type wrapper struct {
	closer closer
}

var (
	aCloser  = closer{}
	aWrapper = wrapper{aCloser}
)

func callCloser(res *http.Response) bool { // want callCloser:"is not closer"
	defer aWrapper.closer.closeBody(res.Body)

	return true
}

func main() {
	reader := doReq()

	defer aCloser.closeBody(reader)

	req := doReq2() // want "req.Body \\(io.ReadCloser\\) was not closed"

	_ = callCloser(req)
}
