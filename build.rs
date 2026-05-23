use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set by Cargo")?);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    fs::write(out_dir.join("httpserver-cert.der"), cert.cert.der())?;
    fs::write(
        out_dir.join("httpserver-key.der"),
        cert.key_pair.serialize_der(),
    )?;
    Ok(())
}
