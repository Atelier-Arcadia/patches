use std::cmp::{PartialOrd, Ordering};

use serde::ser::Serialize;
use serde::de::Deserialize;


/// Contains information describing a package installed on a host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Package {
  pub name: String,
  pub version: String,
}

impl Package {
  /// Construct a package with a name and specific version.
  pub fn new<S1, S2>(name: S1, ver: S2) -> Self
    where S1: Into<String>,
          S2: Into<String>,
  {
    Package {
      name: name.into(),
      version: ver.into(),
    }
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
    let p1 = Package::new("mig", "3.14.15");
    let p2 = Package::new("mig", "2.1.8");
    let p3 = Package::new("mozdef", "10.42.1");
    let p4 = Package::new("mig", "3.14.15");
    let p5 = Package::new("mozdef", "3.14.15");

    assert!(p1 != p2);
    assert!(p2 != p3);
    assert!(p3 != p4);

    assert!(p1 == p4);

    assert!(p1.partial_cmp(&p2).unwrap() == Ordering::Greater);
    assert!(p1.partial_cmp(&p5).is_none());
  }
}
