.PHONY: build test test-internal vet clean install fmt lint security-check setup-hooks check

export PATH := /usr/local/go/bin:$(PATH)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.6.0")
LDFLAGS := -s -w -X main.version=$(VERSION)

vet:
	go vet ./cmd/... ./internal/...

fmt:
	go fmt ./cmd/... ./internal/...

lint: vet
	@echo "Checking gofmt formatting..."
	@unformatted=$$(gofmt -l cmd/ internal/); \
	if [ -n "$$unformatted" ]; then \
		echo "Files need formatting:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "Formatting clean."

security-check:
	@echo "Running bank-grade security invariant checks..."
	@echo "1. Checking for forbidden file writes..."
	@! grep -rnE 'os\.(Create|WriteFile|OpenFile|Remove|RemoveAll|Rename|Chmod|Chown|Truncate)' cmd/ internal/ --exclude='*_test.go'
	@echo "2. Checking for forbidden subprocess execution..."
	@! grep -rnE '(exec\.Command|os\.StartProcess|syscall\.Exec)' cmd/ internal/ --exclude='*_test.go'
	@echo "3. Checking for forbidden network sockets..."
	@! grep -rnE '(net\.Dial|net\.Listen|http\.Get|http\.Post)' internal/ --exclude='*_test.go'
	@echo "4. Checking for forbidden sensitive paths..."
	@! grep -rnE '(\/environ|\/maps|\/mem\b|\/etc\/shadow)' internal/collector/ --exclude='*_test.go'
	@echo "All security invariants PASS."


setup-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*
	@echo "Successfully configured Git hooks to .githooks/"

check: lint security-check test

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/why-slow ./cmd/why-slow/

test:
	go vet ./cmd/... ./internal/...
	go test -race -count=1 ./internal/...
	go test -race -count=1 ./internal_tests/battle_test.go

test-internal:
	go test -race -count=1 ./internal/...

test-battle:
	go test -v -race -count=1 ./internal_tests/battle_test.go

clean:
	rm -rf bin/ /tmp/why-slow*

install: build
	sudo install -m 0755 bin/why-slow /usr/local/bin/why-slow

