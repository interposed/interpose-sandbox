.PHONY: build test tidy clean install help

BIN := ./bin/interpose-sandbox

help:
	@echo "interpose-sandbox build targets:"
	@echo "  make build      # build CLI to ./bin/interpose-sandbox"
	@echo "  make test       # unit tests"
	@echo "  make tidy       # go mod tidy"
	@echo "  make install    # go install to GOPATH/bin"
	@echo "  make clean      # rm ./bin/"

build:
	mkdir -p ./bin
	go build -o $(BIN) ./cmd/interpose-sandbox

test:
	go test -count=1 -timeout=30s ./...

tidy:
	go mod tidy

install:
	go install ./cmd/interpose-sandbox

clean:
	rm -rf ./bin/
