BIN   := image-proxy
GO    := go
LDFLAGS := -ldflags='-s -w'

.PHONY: all build test lint vet clean run coverage fmt

all: clean fmt vet test build

build:
	$(GO) build $(LDFLAGS) -o $(BIN) .

run:
	$(GO) run .

test:
	$(GO) test -v -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

lint:
	golangci-lint run

coverage:
	$(GO) test -race -count=1 -coverprofile=coverage.txt -covermode=atomic ./...
	$(GO) tool cover -html=coverage.txt -o coverage.html

clean:
	rm -f $(BIN)
	rm -rf dist/
	rm -f coverage.txt coverage.html
	rm -f cpu.pprof mem.pprof
