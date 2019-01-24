package rpm

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/Atelier-Arcadia/patches/pkg/pack"
)

type RPM struct {
	compareFn pack.VersionCompareFunc
}

// NewRPM constructs a new RPM that will compare versions using a
// given comparison function.
func NewRPM(cmp pack.VersionCompareFunc) RPM {
	return RPM{
		compareFn: cmp,
	}
}

// Scan invokes rpm, parses the output for lines containing
// the name and version of a package, and determines if the
// package being scanned for is present.
func (rpm RPM) Scan(pkg pack.Package) (pack.Found, error) {
	var output, err = exec.Command(
		"rpm",
		"-qa",
		"--queryformat",
		"%{NAME} %{EVR}\\n").Output()
	if err != nil {
		return pack.NotFound, err
	}

	var packagesFound = parseRPMOutput(output)

	var found = pack.Package{}
	for _, found = range packagesFound {
		var containsName = strings.Contains(found.Name, pkg.Name)
		var sameVersion = rpm.compareFn(pkg.Version, found.Version) == pack.WasFound

		if containsName && sameVersion {
			return pack.WasFound, nil
		}
	}

	return pack.NotFound, nil
}

func parseRPMOutput(output []byte) []pack.Package {
	var lines = bytes.Split(output, []byte("\n"))
	var packages = []pack.Package{}

	var bytesLine = []byte{}
	for _, bytesLine = range lines {
		bytesLine = bytes.Trim(bytesLine, "\t\r ")
		var fields = bytes.Fields(bytesLine)

		if len(fields) < 2 {
			continue
		}

		packages = append(packages, pack.Package{
			Name:    string(fields[0]),
			Version: string(fields[1]),
		})
	}

	return packages
}
