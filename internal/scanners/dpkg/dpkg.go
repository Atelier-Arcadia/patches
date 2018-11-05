package dpkg

import (
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
	return pack.NotFound, nil
}
