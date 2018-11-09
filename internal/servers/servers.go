package servers

import (
	"net/http"

	"github.com/zsck/patches/pkg/vulnerability"
)

type ClairVulnServer struct {
	vulnSource vulnerability.Source
}

func NewClairVulnServer(source vulnerability.Source) ClairVulnServer {
	return ClairVulnServer{
		vulnSource: source,
	}
}

func (server ClairVulnServer) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	res.Write([]byte("Hello, world"))
}
