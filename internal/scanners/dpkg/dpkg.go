package dpkg

import (
	"github.com/zsck/patches/pkg/pack"
)

type DPKG struct{}

func NewScanner() DPKG {
	return DPKG{}
}

func (dpkg DPKG) Scan(pkg pack.Package) (pack.Found, error) {
	return pack.NotFound, nil
}
