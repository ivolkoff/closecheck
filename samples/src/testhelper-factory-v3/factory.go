package testhelper_factory_v3

import (
	"github.com/ivolkoff/closecheck/samples/src/testhelper-asset"
	"github.com/ivolkoff/closecheck/samples/src/testhelper-db"
)

type Factory struct {
	DB *testhelper_asset.Asset[*testhelper_db.DB]

	shutdownHandlers []func()
}

func (a *Factory) Shutdown() {
	for _, handler := range a.shutdownHandlers {
		handler()
	}
}

func (a *Factory) GetDB() *testhelper_db.DB {
	if a.DB != nil {
		return a.DB.Resource()
	}

	a.DB, _ = testhelper_asset.New(
		func() (*testhelper_db.DB, error) { return testhelper_db.InitDB(), nil },
		func(db *testhelper_db.DB) { _ = db.Close() },
	)

	a.shutdownHandlers = append(a.shutdownHandlers, a.DB.Shutdown)

	return a.DB.Resource()
}
