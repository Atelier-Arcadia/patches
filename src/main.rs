extern crate clap;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

mod never;
mod package;
mod vulnerability;

use std::path::Path;

use clap::{Arg, App};

pub use never::Never;
use package::Detect;


const ABOUT: &'static str = "Check if a package is installed with Homebrew";

fn main() {
  let matches = App::new("patches")
    .version("0.0.1")
    .author("Zack Mullaly <zsck@riseup.net>")
    .about(ABOUT)
    .arg(Arg::with_name("package")
      .short("p")
      .long("package")
      .required(true)
      .takes_value(true)
      .help("The name of a package to search for"))
    .arg(Arg::with_name("version")
      .short("v")
      .long("version")
      .required(true)
      .takes_value(true)
      .help("The semantic version of the package to search for. E.g. 1.2.3"))
    .arg(Arg::with_name("directory")
      .short("d")
      .long("directory")
      .required(false)
      .takes_value(true)
      .help("A directory to search for packages in. Defaults to the default Homebrew package directory"))
    .get_matches();

  let (detect, pkg) = match (matches.value_of("package"), matches.value_of("version"), matches.value_of("directory")) {
    (Some(package), Some(version), Some(directory)) =>
      ( package::macos::Homebrew::with_base_dir(Path::new(directory)),
        package::Package::new(package, version),
      ),
    (Some(package), Some(version), _) =>
      ( package::macos::Homebrew::new(),
        package::Package::new(package, version),
      ),
    _ => panic!("Missing required values"),
  };

  match detect.detect(&pkg) {
    Ok(true)  => println!("Installed"),
    Ok(false) => println!("Not installed"),
    Err(err)  => panic!("{:?}", err),
  }
}
