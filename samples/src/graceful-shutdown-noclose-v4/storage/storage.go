package storage

import testhelper_db "github.com/ivolkoff/closecheck/samples/src/testhelper-db"

type Storage struct {
	db *testhelper_db.DB
}

func NewStorage(db *testhelper_db.DB) *Storage {
	return &Storage{db: db}
}
