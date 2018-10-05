use std::cmp::{PartialOrd, Ordering};

use semver::{SemVerError, Version};


// Contains information describing a package installed on a host.
#[derive(Clone, Debug)]
pub struct Package {
  pub name: String,
  pub version: Version,
}

impl Package {
  // Construct a package with a name and specific version.
  pub fn new<S: Into<String>>(name: S, ver: Version) -> Self {
    Package {
      name: name.into(),
      version: ver,
    }
  }

  // Attempt to construct a package with a name and a version.
  // Here, the version is given as a string which is parsed with the assumption that
  // it describes a semantic version.
  pub fn with_version_string<S1, S2>(name: S1, ver: S2) -> Result<Package, SemVerError>
    where S1: Into<String>,
          S2: AsRef<str>,
  {
    Version::parse(ver.as_ref())
      .map(|version| Package {
        name: name.into(),
        version: version,
      })
  }
}

impl PartialEq for Package {
  fn eq(&self, other: &Package) -> bool {
    self.name == other.name && self.version == other.version
  }
}

impl Eq for Package{}

impl PartialOrd for Package {
  fn partial_cmp(&self, other: &Package) -> Option<Ordering> {
    if self.name != other.name {
      None
    } else {
      self.version.partial_cmp(&other.version)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use std::cmp::{PartialOrd, Ordering};


  #[test]
  fn package_comparison() {
    let p1 = Package::with_version_string("mig", "3.14.15").unwrap();
    let p2 = Package::with_version_string("mig", "2.1.8").unwrap();
    let p3 = Package::with_version_string("mozdef", "10.42.1").unwrap();
    let p4 = Package::with_version_string("mig", "3.14.15").unwrap();
    let p5 = Package::with_version_string("mozdef", "3.14.15").unwrap();

    assert!(p1 != p2);
    assert!(p2 != p3);
    assert!(p3 != p4);

    assert!(p1 == p4);

    assert!(p1.partial_cmp(&p2).unwrap() == Ordering::Greater);
    assert!(p1.partial_cmp(&p5).is_none());
  }
}
