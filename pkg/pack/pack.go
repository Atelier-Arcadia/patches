package pack

// Scanner describes types that support the behaviour of scanning the host for
// an installation of a given package.
type Scanner interface {
	Scan(Package) (Found, error)
}

// Package describes a software package that may be installed on a host.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"name"`
}

// Found is a descriptive alias for a boolean produced by a Scanner that has
// performed a scan for a particular package.
type Found bool

const (
	WasFound Found = true
	NotFound Found = false
)
