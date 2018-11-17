package platform

// Platform describes a Linux distribution for which the Clair API can provide
// information about vulnerable packages.
type Platform struct {
	distro  string
	version string
}

var (
	CentOS5 Platform = Platform{
		distro:  "centos",
		version: "5",
	}
	CentOS6 Platform = Platform{
		distro:  "centos",
		version: "6",
	}
	CentOS7 Platform = Platform{
		distro:  "centos",
		version: "7",
	}
	Debian8 Platform = Platform{
		distro:  "debian",
		version: "8",
	}
	Debian9 Platform = Platform{
		distro:  "debian",
		version: "9",
	}
	Debian10 Platform = Platform{
		distro:  "debian",
		version: "10",
	}
	DebianUnstable Platform = Platform{
		distro:  "debian",
		version: "unstable",
	}
	Alpine3_3 Platform = Platform{
		distro:  "alpine",
		version: "v3.3",
	}
	Alpine3_4 Platform = Platform{
		distro:  "alpine",
		version: "v3.4",
	}
	Alpine3_5 Platform = Platform{
		distro:  "alpine",
		version: "v3.5",
	}
	Alpine3_6 Platform = Platform{
		distro:  "alpine",
		version: "v3.6",
	}
	Alpine3_7 Platform = Platform{
		distro:  "alpine",
		version: "v3.7",
	}
	Alpine3_8 Platform = Platform{
		distro:  "alpine",
		version: "v3.8",
	}
	Oracle5 Platform = Platform{
		distro:  "oracle",
		version: "5",
	}
	Oracle6 Platform = Platform{
		distro:  "oracle",
		version: "6",
	}
	Oracle7 Platform = Platform{
		distro:  "oracle",
		version: "7",
	}
	Ubuntu12_04 Platform = Platform{
		distro:  "ubuntu",
		version: "12.04",
	}
	Ubuntu12_10 Platform = Platform{
		distro:  "ubuntu",
		version: "12.10",
	}
	Ubuntu13_04 Platform = Platform{
		distro:  "ubuntu",
		version: "13.04",
	}
	Ubuntu13_10 Platform = Platform{
		distro:  "ubuntu",
		version: "13.10",
	}
	Ubuntu14_04 Platform = Platform{
		distro:  "ubuntu",
		version: "14.04",
	}
	Ubuntu14_10 Platform = Platform{
		distro:  "ubuntu",
		version: "14.10",
	}
	Ubuntu15_04 Platform = Platform{
		distro:  "ubuntu",
		version: "15.04",
	}
	Ubuntu15_10 Platform = Platform{
		distro:  "ubuntu",
		version: "15.10",
	}
	Ubuntu16_04 Platform = Platform{
		distro:  "ubuntu",
		version: "16.04",
	}
	Ubuntu16_10 Platform = Platform{
		distro:  "ubuntu",
		version: "16.10",
	}
	Ubuntu17_04 Platform = Platform{
		distro:  "ubuntu",
		version: "17.04",
	}
	Ubuntu17_10 Platform = Platform{
		distro:  "ubuntu",
		version: "17.10",
	}
	Ubuntu18_04 Platform = Platform{
		distro:  "ubuntu",
		version: "18.04",
	}
)

// Translate converts a platform name into its internal representation.
// The naming scheme used is: distro-M(.m.p(-.*)?)
func Translate(name string) (Platform, bool) {
	supported := map[string]Platform{
		"centos-6":        CentOS6,
		"centos-7":        CentOS7,
		"debian-8":        Debian8,
		"debian-9":        Debian9,
		"debian-10":       Debian10,
		"debian-unstable": DebianUnstable,
	}

	pform, found := supported[name]
	if !found {
		return Platform{}, false
	}

	return pform, true
}

func (p Platform) String() string {
	// TODO - this String definition will only work for Clair
	return p.distro + ":" + p.version
}
