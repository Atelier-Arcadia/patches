package dpkg

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/zsck/patches/pkg/pack"
)

type DPKG struct {
	compareFn pack.VersionCompareFunc
}

func NewScanner(cmp pack.VersionCompareFunc) DPKG {
	return DPKG{
		compareFn: cmp,
	}
}

func (dpkg DPKG) Scan(pkg pack.Package) (pack.Found, error) {
	output, err := exec.Command("dpkg", "-l", pkg.Name).Output()
	if err != nil {
		if err.Error() == "exit status 1" {
			return pack.NotFound, nil
		}
		return pack.NotFound, err
	}

	for _, bytesLine := range bytes.Split(output, []byte("\n")) {
		bytesLine = bytes.Trim(bytesLine, "\t\r ")
		strLine := string(bytesLine)

		if strings.Contains(strLine, "ii") {
			encounteredName := false
			tokens := strings.Split(strLine, " ")

			for _, token := range tokens {
				if len(token) < 2 || token == "ii" {
					continue
				}
				if encounteredName {
					// Found the version
					version := token
					return dpkg.compareFn(pkg.Version, version), nil
				}
				if strings.Contains(pkg.Name, token) {
					encounteredName = true
					continue
				}
			}
		}
	}
	return pack.NotFound, nil
}
