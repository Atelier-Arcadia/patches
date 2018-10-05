pub mod macos;
mod package;

pub use package::package::Package;


/// An interface for different means of searching for a package on a host.
pub trait Detect {
  type Error;

  /// Determine whether a given package is installed.
  fn detect(&self, &Package) -> Result<bool, Self::Error>;
}
