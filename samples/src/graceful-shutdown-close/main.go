package main

import (
	"github.com/ivolkoff/closecheck/samples/src/testhelper-asset"
	"github.com/ivolkoff/closecheck/samples/src/testhelper-db"
	"github.com/ivolkoff/closecheck/samples/src/testhelper-factory"
)

func main() {
	factory := &testhelper_factory.Factory{}
	defer factory.Shutdown()

	factory.DB, _ = testhelper_asset.New(
		func() (*testhelper_db.DB, error) { return testhelper_db.InitDB(), nil },
		func(db *testhelper_db.DB) { _ = db.Close() },
	)
	factory.AddShutdown(factory.DB.Shutdown)

	storage := NewStorage(factory.DB.Resource())
	_ = storage
}

type Storage struct {
	db *testhelper_db.DB
}

func NewStorage(db *testhelper_db.DB) *Storage {
	return &Storage{db: db}
}
