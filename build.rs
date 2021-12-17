use cc;
use std::path::Path;


fn main() {
    println!("cargo:rustc-link-arg=-lpari");
    cc::Build::new().file("src/hpari.c").flag("-v").compile("libhpari.a");
}
