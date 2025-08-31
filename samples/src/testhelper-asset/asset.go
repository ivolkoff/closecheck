package testhelper_asset

import "fmt"

type Asset[T any] struct {
	resource T
	shutdown func(T)
}

func (a *Asset[T]) Resource() T {
	return a.resource
}

func (a *Asset[T]) Shutdown() {
	a.shutdown(a.resource)
}

func New[T any](init func() (T, error), shutdown func(T)) (*Asset[T], error) {
	resource, err := init()
	if err != nil {
		return nil, fmt.Errorf("error initializing asset: %v", err)
	}

	return &Asset[T]{
		resource: resource,
		shutdown: shutdown,
	}, nil
}
