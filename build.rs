extern crate rustc_version;
use rustc_version::{version, Version};

extern crate vergen;
use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let version = version().expect("Failed to get rustc version.");
    if version < Version::parse("1.42.0").unwrap() {
        eprintln!(
            "\n\nAt least Rust version 1.42 is required.\n\
             Version {version} is used for building.\n\
             Build aborted.\n\n"
        );
        panic!();
    }

    let flags = ConstantsFlags::SHA_SHORT | ConstantsFlags::REBUILD_ON_HEAD_CHANGE;
    generate_cargo_keys(flags).expect("Unable to generate version env vars!");
}
