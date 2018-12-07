unit-test:
	go test ./internal/clients/
	go test ./internal/limit/
	go test ./internal/scanners/
	go test ./internal/sources/
	go test ./internal/sources/clair/
	go test ./internal/servers/
	go test ./cmd/scanner/

test: unit-test

install-dependencies:
	go get github.com/Sirupsen/logrus

build-server:
	go build -o patchesserver. ./cmd/server

build-scanner:
	go build -o patchesscanner. ./cmd/scanner

docker-image:
	docker build -t patches .
