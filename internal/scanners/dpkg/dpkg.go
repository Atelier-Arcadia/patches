package dpkg

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/arcrose/patches/pkg/pack"
)

// DPKG is a Scanner that searches for installed packages by invoking dpkg.
type DPKG struct {
	compareFn pack.VersionCompareFunc
}

// NewScanner constructs a new DPKG that will compare versions using a
// given comparison function.
func NewScanner(cmp pack.VersionCompareFunc) DPKG {
	return DPKG{
		compareFn: cmp,
	}
}

// Scan invokes dpkg, parses the output for lines containing findings,
// and then searches for the package being inquired about specifically.
func (dpkg DPKG) Scan(pkg pack.Package) (pack.Found, error) {
	output, err := exec.Command("dpkg", "-l", pkg.Name).Output()
	if err != nil {
		if err.Error() == "exit status 1" {
			return pack.NotFound, nil
		}
		return pack.NotFound, err
	}

	packagesFound := parseDpkgOutput(output)
	for _, found := range packagesFound {
		containsName := strings.Contains(found.Name, pkg.Name)
		sameVersion := dpkg.compareFn(pkg.Version, found.Version) == pack.WasFound

		if containsName && sameVersion {
			return pack.WasFound, nil
		}
	}
	return pack.NotFound, nil
}

func parseDpkgOutput(output []byte) []pack.Package {
	lines := bytes.Split(output, []byte("\n"))
	packages := []pack.Package{}

	for _, bytesLine := range lines {
		bytesLine = bytes.Trim(bytesLine, "\t\r ")
		strLine := string(bytesLine)

		if strings.Contains(strLine, "ii") {
			encounteredName := ""
			tokens := strings.Split(strLine, " ")

			for _, token := range tokens {
				if len(token) < 2 || token == "ii" {
					continue
				}
				if encounteredName == "" {
					encounteredName = token
					continue
				} else {
					packages = append(packages, pack.Package{
						Name:    encounteredName,
						Version: token,
					})
					break
				}
			}
		}
	}

	return packages
}
