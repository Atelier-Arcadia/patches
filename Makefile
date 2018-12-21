unit-test:
	go test -v ./internal/clients/
	go test -v ./internal/limit/
	go test -v ./internal/scanners/
	go test -v ./internal/sources/
	go test -v ./internal/sources/clair/
	go test -v ./internal/servers/
	go test -v ./cmd/scanner/

test: unit-test

dependencies:
	go get github.com/Sirupsen/logrus

server:
	go build -o patchesserver ./cmd/server

scanner:
	go build -o patchesscanner ./cmd/scanner

docker-image:
	docker build -t patches .
