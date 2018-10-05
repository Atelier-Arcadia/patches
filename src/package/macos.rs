use std::default::Default;
use std::path::Path;

use Never;
use package::{Detect, Package};


/// An implementation of `Detect` that searches for a package within the `Cellar/`
/// directory that [Homebrew](https://brew.sh/) installs packages to.
///
/// This type performs a simple check that involves looking for a directory in
/// `base_dir/package_name/major.minor.patch/` to determine if a package is installed.
pub struct Homebrew<P> {
  pub base_dir: P,
}

impl Homebrew<&'static Path> {
  /// Construct a `Homebrew` package detector that checks for packages in the
  /// default `/usr/local/Cellar/` directory.
  pub fn new() -> Self {
    Default::default()
  }
}

impl<P: AsRef<Path>> Homebrew<P> {
  /// Construct a `Homebrew` that will look for packages in a given base directory.
  pub fn with_base_dir(path: P) -> Self {
    Homebrew {
      base_dir: path,
    }
  }
}

impl Default for Homebrew<&'static Path> {
  fn default() -> Self {
    Homebrew {
      base_dir: Path::new("/usr/local/Cellar/"),
    }
  }
}

impl<P: AsRef<Path>> Detect for Homebrew<P> {
  type Error = Never;

  fn detect(&self, pkg: &Package) -> Result<bool, Self::Error> {
    let package_dir = format!(
      "{}/{}.{}.{}",
      pkg.name,
      pkg.version.major,
      pkg.version.minor,
      pkg.version.patch);
    let ext = Path::new(&package_dir);
    let file_path = self.base_dir.as_ref().join(ext);

    Ok(file_path.exists())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use std::fs;

  use package::Package;


  #[test]
  fn finds_installed_packages() {
    let hb = Homebrew::with_base_dir("/tmp");
    let package = Package::with_version_string("packagename", "1.2.3").unwrap();

    fs::create_dir_all("/tmp/packagename/1.2.3").unwrap();

    assert!(hb.detect(&package).unwrap());
  }
  
  #[test]
  fn does_not_find_packages_that_are_not_installed() {
    let hb = Homebrew::new();
    let package = Package::with_version_string("packagename", "3.2.1").unwrap();

    assert!(!hb.detect(&package).unwrap());
  }
}
