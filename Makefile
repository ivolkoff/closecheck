.PHONY: build test clean

build:
	go build -o ./bin/closecheck .

test:
	go test ./...

clean:
	rm -f ./bin

all: clean test build
