package main

import (
	"github.com/ivolkoff/closecheck/samples/src/testhelper-db"
	testhelper_factory "github.com/ivolkoff/closecheck/samples/src/testhelper-factory-v3"
)

func main() {
	factory := &testhelper_factory.Factory{}
	defer factory.Shutdown()

	db := factory.GetDB()

	storage := NewStorage(db)
	_ = storage
}

type Storage struct {
	db *testhelper_db.DB
}

func NewStorage(db *testhelper_db.DB) *Storage {
	return &Storage{db: db}
}
