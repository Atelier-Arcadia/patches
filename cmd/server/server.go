package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/arcrose/patches/internal/servers"
	"github.com/arcrose/patches/internal/sources/clair"

	"github.com/arcrose/patches/internal/limit"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
}

func main() {
	bindPort := flag.Uint("port", 8080, "Port to bind the API server to")
	baseAddr := flag.String("clair", "http://127.0.0.1:6060", "Base address for Clair API")
	maxJobs := flag.Uint("jobs", 128, "Maximum number of clients to serve before rate limiting")
	flag.Parse()

	if *bindPort > 65535 {
		panic(fmt.Errorf("%d is not a valid port number", *bindPort))
	}

	clairConfig := clair.ClairAPIv1{
		BaseURL: *baseAddr,
	}
	rateLimit := limit.ConstantRateLimiter(100 * time.Millisecond)
	options := servers.VulnJobManagerOptions{
		MaxJobs: *maxJobs,
	}
	vulns := clair.NewStream(clairConfig, rateLimit)
	server := servers.NewClairVulnServer(vulns, options)

	http.Handle("/", server)
	http.ListenAndServe(fmt.Sprintf(":%d", *bindPort), nil)
}
