use cc;

fn main() {
    cc::Build::new().file("src/snow2_fast.c").compile("c_snow2");
    println!("cargo:rerun-if-changed=src/snow2.h");
    println!("cargo:rerun-if-changed=src/snow2tab.h");
    println!("cargo:rerun-if-changed=src/snow2_fast.c");
}
