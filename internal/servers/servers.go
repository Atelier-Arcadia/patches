package servers

import (
	"fmt"
	"net/http"
)

type ClairVulnServer struct {
}

func NewClairVulnServer() ClairVulnServer {
	return ClairVulnServer{}
}

func (server ClairVulnServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("Hello, world"))
}
