use std::io::{self, Read, Write};

use crate::deps::DirFs;

#[derive(Clone, Copy)]
pub enum Algo {
    Md5,
    Sha256,
}

pub fn run(out: &mut impl Write, fs: &impl DirFs, algo: Algo, args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        writeln!(out, "{}  -", hash_bytes(algo, &data))?;
        return Ok(());
    }

    for path in args {
        if path == "-" {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data)?;
            writeln!(out, "{}  -", hash_bytes(algo, &data))?;
        } else {
            match fs.read_bytes(path) {
                Ok(data) => writeln!(out, "{}  {path}", hash_bytes(algo, &data))?,
                Err(e) => eprintln!("{path}: {e}"),
            }
        }
    }

    Ok(())
}

fn hash_bytes(algo: Algo, data: &[u8]) -> String {
    use sha2::Digest;
    let bytes: Vec<u8> = match algo {
        Algo::Md5 => md5::Md5::digest(data).to_vec(),
        Algo::Sha256 => sha2::Sha256::digest(data).to_vec(),
    };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{DirFs, Fs};
    use std::collections::HashMap;

    struct FakeFs(HashMap<String, Vec<u8>>);

    impl FakeFs {
        fn new(files: &[(&str, &[u8])]) -> Self {
            Self(files.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect())
        }
    }

    impl Fs for FakeFs {
        fn read(&self, path: &str) -> io::Result<String> {
            self.read_bytes(path).map(|b| String::from_utf8_lossy(&b).into_owned())
        }
        fn write(&self, _: &str, _: &str) -> io::Result<()> {
            unimplemented!()
        }
    }

    impl DirFs for FakeFs {
        fn read_bytes(&self, path: &str) -> io::Result<Vec<u8>> {
            self.0.get(path).cloned().ok_or_else(|| io::Error::other("not found"))
        }
        fn is_dir(&self, _: &str) -> bool { false }
        fn list_dir(&self, _: &str) -> io::Result<Vec<String>> { Ok(vec![]) }
    }

    #[test]
    fn md5_empty() {
        let fs = FakeFs::new(&[("f", b"")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Md5, &["f".into()]).unwrap();
        assert_eq!(out, b"d41d8cd98f00b204e9800998ecf8427e  f\n");
    }

    #[test]
    fn md5_known() {
        let fs = FakeFs::new(&[("f", b"hello world\n")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Md5, &["f".into()]).unwrap();
        assert_eq!(out, b"6f5902ac237024bdd0c176cb93063dc4  f\n");
    }

    #[test]
    fn sha256_empty() {
        let fs = FakeFs::new(&[("f", b"")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Sha256, &["f".into()]).unwrap();
        assert_eq!(
            out,
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  f\n"
        );
    }

    #[test]
    fn sha256_known() {
        let fs = FakeFs::new(&[("f", b"hello world\n")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Sha256, &["f".into()]).unwrap();
        assert_eq!(
            out,
            b"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  f\n"
        );
    }

    #[test]
    fn multiple_files() {
        let fs = FakeFs::new(&[("a", b"foo"), ("b", b"bar")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Sha256, &["a".into(), "b".into()]).unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("  a\n"));
        assert!(body.contains("  b\n"));
    }

    #[test]
    fn missing_file_continues() {
        let fs = FakeFs::new(&[("exists", b"data")]);
        let mut out = Vec::new();
        run(&mut out, &fs, Algo::Md5, &["missing".into(), "exists".into()]).unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("exists"));
        assert!(!body.contains("missing"));
    }
}
