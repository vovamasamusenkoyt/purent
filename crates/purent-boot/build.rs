fn main() {
    println!("cargo:rerun-if-changed=../../target/esp/purentoskrnl.exe");
    println!("cargo:rerun-if-changed=src/main.rs");
}
