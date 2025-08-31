package factory

import (
	"github.com/ivolkoff/closecheck/samples/src/testhelper-asset"
	"github.com/ivolkoff/closecheck/samples/src/testhelper-db"
)

type BaseConfig struct {
}

func (c BaseConfig) isStruct() {}

type StructConstraint interface {
	isStruct()
}

type Factory[Conf StructConstraint] struct {
	DB *testhelper_asset.Asset[*testhelper_db.DB]

	config Conf

	shutdownHandlers []func()
}

func (f *Factory[S]) Clean() {
	for _, handler := range f.shutdownHandlers {
		handler()
	}
}

func (f *Factory[S]) GetDB() *testhelper_db.DB {
	if f.DB != nil {
		return f.DB.Resource()
	}

	f.DB, _ = testhelper_asset.New(
		func() (*testhelper_db.DB, error) { return testhelper_db.InitDB(), nil },
		func(db *testhelper_db.DB) { _ = db.Close() },
	)

	f.shutdownHandlers = append(f.shutdownHandlers, f.DB.Shutdown)

	return f.DB.Resource()
}
