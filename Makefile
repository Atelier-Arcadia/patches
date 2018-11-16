unit-test:
	go test ./internal/scanners/clair/

test:
	docker build -t patches .
	docker-compose up --abort-on-container-exit

deps:
	go get github.com/Sirupsen/logrus
