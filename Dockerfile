FROM golang:latest

WORKDIR /src/github.com/Atelier-Arcadia/patches/

ENV GOPATH /

COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
COPY patches.go patches.go
COPY Makefile Makefile

RUN make install-dependencies
RUN make build-server

CMD ["./patchesserver", "-clair", "http://clair:6060"]
