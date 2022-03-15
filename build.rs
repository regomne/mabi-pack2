use cc;

fn main() {
    cc::Build::new()
        .file("src/enc_table.c")
        .file("src/enc.c")
        .compile("dec_table");
    println!("cargo:rerun-if-changed=src/enc_table.c");
    println!("cargo:rerun-if-changed=src/enc.c");
}
