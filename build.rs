use cc;
use std::path::Path;


fn main() {
    println!("cargo:rustc-link-arg=-lpari");
    let library_path = Path::new("/opt/homebrew/include");
    cc::Build::new().include(library_path).file("src/hpari.c").flag("-v").compile("libhpari.a");
}
