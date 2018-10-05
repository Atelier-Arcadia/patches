use std::cmp::{PartialOrd, Ordering};

use serde::ser::Serialize;
use serde::de::Deserialize;

use semver::{SemVerError, Version};


/// A container for the textual representation of a `Package`.
///
/// # Examples
///
/// ```
/// let desc = Description {
///   name = "package".to_string(),
///   version = "1.2.3".to_string(),
/// };
/// let pkg = Package::with_version_string(desc.name, desc.version).unwrap();
/// ```
///
/// ```
/// let pkg = Package::new("package", Version {
///   major: 1,
///   minor: 2,
///   patch: 3,
///   pre: vec![],
///   build: vec![],
/// });
/// let desc: Description = From::from(pkg);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Description {
  pub name: String,
  pub version: String,
}

/// Contains information describing a package installed on a host.
#[derive(Clone, Debug)]
pub struct Package {
  pub name: String,
  pub version: Version,
}

impl Description {
  /// Construct a representation of a `Package` that can be easily
  /// serialized and deserialized.
  pub fn new<S1, S2>(name: S1, ver: S2) -> Self
    where S1: Into<String>,
          S2: Into<String>,
  {
    Description {
      name: name.into(),
      version: ver.into(),
    }
  }
}

impl Package {
  /// Construct a package with a name and specific version.
  pub fn new<S: Into<String>>(name: S, ver: Version) -> Self {
    Package {
      name: name.into(),
      version: ver,
    }
  }

  /// Attempt to construct a package with a name and a version.
  /// Here, the version is given as a string which is parsed with the assumption that
  /// it describes a semantic version.
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

impl From<Package> for Description {
  fn from(pkg: Package) -> Self {
    Description {
      name: pkg.name,
      version: format!("{}", pkg.version),
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
