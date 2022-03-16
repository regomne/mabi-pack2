use cc;

fn main() {
    cc::Build::new()
        .file("src/enc_table.c")
        .file("src/enc.c")
        .compile("c_enc");
    println!("cargo:rerun-if-changed=src/enc_table.c");
    println!("cargo:rerun-if-changed=src/enc.c");
}
