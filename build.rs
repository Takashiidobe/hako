use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if env::var_os("CARGO_FEATURE_EMBEDDED_TLS").is_none() {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed httpserver cert");
    fs::write(out_dir.join("httpserver-cert.der"), cert.cert.der())
        .expect("write httpserver cert");
    fs::write(out_dir.join("httpserver-key.der"), cert.key_pair.serialize_der())
        .expect("write httpserver key");
}
