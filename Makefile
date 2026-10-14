.PHONY: build test tidy clean install help

help:
	@echo "interpose-sandbox build targets:"
	@echo "  make build      # build interpose-ci + interpose-cell to ./bin/"
	@echo "  make test       # unit tests"
	@echo "  make tidy       # go mod tidy"
	@echo "  make install    # go install to GOPATH/bin"
	@echo "  make clean      # rm ./bin/"

build:
	mkdir -p ./bin
	go build -o ./bin/interpose-ci   ./cmd/interpose-ci
	go build -o ./bin/interpose-cell ./cmd/interpose-cell

test:
	go test -count=1 -timeout=30s ./...

tidy:
	go mod tidy

install:
	go install ./cmd/interpose-ci ./cmd/interpose-cell

clean:
	rm -rf ./bin/
