.PHONY: build clean test

build:
	go mod download
	go build -o bin/netprowl-agent ./cmd/agent

build-all:
	GOOS=linux   GOARCH=amd64 go build -o bin/netprowl-agent-linux-amd64   ./cmd/agent
	GOOS=linux   GOARCH=arm64 go build -o bin/netprowl-agent-linux-arm64   ./cmd/agent
	GOOS=linux   GOARCH=arm  GOARM=7 go build -o bin/netprowl-agent-linux-armv7 ./cmd/agent
	GOOS=darwin  GOARCH=amd64 go build -o bin/netprowl-agent-darwin-amd64  ./cmd/agent
	GOOS=darwin  GOARCH=arm64 go build -o bin/netprowl-agent-darwin-arm64  ./cmd/agent

test:
	go test ./...

clean:
	rm -rf bin/