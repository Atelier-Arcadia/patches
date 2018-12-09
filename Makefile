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

server:
	go build -o patchesserver ./cmd/server

scanner:
	go build -o patchesscanner ./cmd/scanner

docker-image:
	docker build -t patches .
