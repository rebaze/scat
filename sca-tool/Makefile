VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -X github.com/rebaze/starter-sbom-toolchain/sca-tool/cmd.version=$(VERSION) \
             -X github.com/rebaze/starter-sbom-toolchain/sca-tool/cmd.commit=$(COMMIT) \
             -X github.com/rebaze/starter-sbom-toolchain/sca-tool/cmd.date=$(DATE)
BIN       := sca-tool

.PHONY: build run clean vet tidy

## build: compile the sca-tool binary
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

## run: build then run 'analyze' on a target (set TARGET=<dir>)
##   example: make run TARGET=../some-project
run: build
	@[ -n "$(TARGET)" ] || { echo "usage: make run TARGET=<dir>"; exit 1; }
	./$(BIN) analyze $(TARGET)

## vet: run go vet
vet:
	go vet ./...

## tidy: tidy and verify module dependencies
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -f $(BIN)
