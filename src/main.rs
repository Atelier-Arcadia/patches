extern crate semver;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

mod never;
mod package;

pub use never::Never;


fn main() {
    println!("Hello, world!");
}
