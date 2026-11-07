VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := bin/scnet2api

.PHONY: build test race vet fmt clean run import probe

build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN).exe .
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/probe.exe ./cmd/probe

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

run: build
	./$(BIN).exe

import: build
	./$(BIN).exe -import

probe:
	go run ./cmd/probe -usage

clean:
	rm -rf bin
