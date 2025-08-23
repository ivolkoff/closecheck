package testhelper

import "io"

func CloseWithDefer(c io.Closer) { // want CloseWithDefer:"is closer"
	doClose(c)
}

func doClose(c io.Closer) { // want doClose:"is closer"
	c.Close()
}