unit-test:
	go test ./internal/clients/
	go test ./internal/limit/
	go test ./internal/scanners/
	go test ./internal/sources/clair/
	go test ./internal/servers/

install-dependencies:
	go get github.com/Sirupsen/logrus

build-server:
	go build -o patchesrv ./cmd/server
