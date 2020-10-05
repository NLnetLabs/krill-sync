extern crate rustc_version;
use rustc_version::{Version, version};

extern crate vergen;
use vergen::{ConstantsFlags, generate_cargo_keys};

fn main() {
    let version = version().expect("Failed to get rustc version.");
    if version < Version::parse("1.42.0").unwrap() {
        eprintln!(
            "\n\nAt least Rust version 1.42 is required.\n\
             Version {} is used for building.\n\
             Build aborted.\n\n",
             version);
        panic!();
    }

    let flags = ConstantsFlags::SHA_SHORT|
                ConstantsFlags::REBUILD_ON_HEAD_CHANGE;
    generate_cargo_keys(flags)
        .expect("Unable to generate version env vars!");
}