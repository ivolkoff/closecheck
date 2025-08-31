package testhelper_db

type DB struct{}

func InitDB() *DB {
	return &DB{}
}

func (db *DB) Close() error {
	print("DB closed")
	return nil
}
