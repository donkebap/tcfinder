extern crate cc;

fn main() {
    std::env::set_var("CFLAGS", "-O2 -msse2 -maes -mpclmul");
    cc::Build::new().file("c_src/gfmul.c").compile("libgfmul.a");
}
