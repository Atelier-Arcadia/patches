package homebrew

import (
	"os"
	"path"

	"github.com/Atelier-Arcadia/patches/pkg/pack"
)

// Homebrew is a Scanner that searches for installed packages by looking for a directory
// with the appropriate name in a particular install directory.
type Homebrew struct {
	installDirectory string
}

// NewHomebrew constructs a new Homebrew.
func NewHomebrew(installDir string) Homebrew {
	return Homebrew{
		installDirectory: installDir,
	}
}

// Scan will look for a directory {installdir}/{packagename}/{packageversion}
// to determine if a particular package is installed by Homebrew.
func (hb Homebrew) Scan(pkg pack.Package) (pack.Found, error) {
	expectedPath := path.Join(hb.installDirectory, pkg.Name, pkg.Version)
	stats, err := os.Stat(expectedPath)
	if err != nil {
		return pack.Notfound, err
	}

	if stats.IsDir() {
		return pack.Found, nil
	}
	return pack.NotFound, nil
}
