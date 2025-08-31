.PHONY: build test clean tidy-all run-samples

build:
	go build -o ./bin/closecheck .

test:
	go test ./...

clean:
	rm -f ./bin

tidy-all:
	find . -name "go.mod" -execdir sh -c 'echo "Processing $$(pwd)" && go mod tidy && go mod vendor' \;

all: clean test build

# Run analyzer against sample packages with flags before patterns
# Usage: make run-samples [FLAGS="-print-statements -enable-function-debugger"]
FLAGS ?= -print-statements
run-samples:
	./bin/closecheck $(FLAGS) ./samples/...
