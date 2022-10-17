use std::env;
use std::path::PathBuf;

fn main() {
    let mut staticdir: PathBuf = env::current_dir().unwrap();
    staticdir.push("static");
    println!("cargo:rustc-link-search={}", staticdir.display().to_string());
}