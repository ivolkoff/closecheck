package main

import (
	pkgfactory "github.com/ivolkoff/closecheck/samples/src/graceful-shutdown/v4/factory"
	pkgstorage "github.com/ivolkoff/closecheck/samples/src/graceful-shutdown/v4/storage"
)

type Config struct {
	pkgfactory.BaseConfig
}

func main() {
	factory := &pkgfactory.Factory[Config]{} // want `not closed`
	// defer factory.Clean()

	db := factory.GetDB()

	storage := pkgstorage.NewStorage(db)
	_ = storage
}
