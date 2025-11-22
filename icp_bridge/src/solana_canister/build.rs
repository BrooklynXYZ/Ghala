fn main() {
    // Skip zstd-sys build for wasm32 targets
    if std::env::var("TARGET").unwrap().contains("wasm32") {
        println!("cargo:rustc-cfg=skip_zstd");
    }
}

