package testhelper_factory

import (
	"github.com/ivolkoff/closecheck/samples/src/testhelper-asset"
	"github.com/ivolkoff/closecheck/samples/src/testhelper-db"
)

type Factory struct {
	DB *testhelper_asset.Asset[*testhelper_db.DB]

	shutdownHandlers []func()
}

func (a *Factory) AddShutdown(handler func()) {
	a.shutdownHandlers = append(a.shutdownHandlers, handler)
}

func (a *Factory) Shutdown() {
	for _, handler := range a.shutdownHandlers {
		handler()
	}
}
