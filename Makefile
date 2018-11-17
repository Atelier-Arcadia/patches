unit-test:
	go test ./internal/limit/
	go test ./internal/sources/clair/
	go test ./internal/servers/

install-dependencies:
	go get github.com/Sirupsen/logrus

build-server:
	go build -o patchesrv ./cmd/server
