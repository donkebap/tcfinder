extern crate gcc;

fn main() {
    std::env::set_var("CFLAGS", "-O2 -msse2 -maes -mpclmul");
    gcc::compile_library("libgfmul.a", &["c_src/gfmul.c"]);
}
