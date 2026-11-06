.PHONY: build linux test clean

build:
	go build -o dist/tim ./cmd/tim

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/tim-linux-amd64 ./cmd/tim
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/tim-linux-arm64 ./cmd/tim

test:
	go vet ./...
	GOOS=linux go vet ./...
	go test ./...

clean:
	rm -rf dist
