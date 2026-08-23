.PHONY: build test test-internal vet clean install fmt

export PATH := /usr/local/go/bin:$(PATH)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.6.0")
LDFLAGS := -s -w -X main.version=$(VERSION)

vet:
	go vet ./cmd/... ./internal/...

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/why-slow ./cmd/why-slow/

fmt:
	go fmt ./cmd/... ./internal/...

test:
	go vet ./cmd/... ./internal/...

test-internal:
	go test -race -count=1 ./internal_tests/analyzer/... ./internal_tests/collector/... ./internal_tests/presenter/...

clean:
	rm -rf bin/ /tmp/why-slow*

install: build
	sudo install -m 0755 bin/why-slow /usr/local/bin/why-slow
