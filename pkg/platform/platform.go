package platform

// Platform describes a Linux distribution for which the Clair API can provide
// information about vulnerable packages.
type Platform struct {
	distro  string
	version string
}

var (
	Debian8 Platform = Platform{
		distro:  "debian",
		version: "8",
	}
)
