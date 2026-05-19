use std::io::{self, Write};

use crate::deps::Fs;

pub fn run(out: &mut impl Write, fs: &impl Fs, args: &[String]) -> io::Result<()> {
    match args {
        [src, dst] => {
            let contents = fs.read(src)?;
            fs.write(dst, &contents)?;
            writeln!(out, "{} -> {}", src, dst)
        }
        _ => Err(io::Error::other("usage: overwrite <src> <dst>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::FakeFs;

    #[test]
    fn copies_contents() {
        let fs = FakeFs::new(&[("a.txt", b"hello")], &[]);
        let mut out = Vec::new();
        run(&mut out, &fs, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert_eq!(fs.file("b.txt"), Some(b"hello".to_vec()));
    }

    #[test]
    fn overwrites_existing() {
        let fs = FakeFs::new(&[("a.txt", b"new"), ("b.txt", b"old")], &[]);
        let mut out = Vec::new();
        run(&mut out, &fs, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert_eq!(fs.file("b.txt"), Some(b"new".to_vec()));
    }

    #[test]
    fn missing_src_errors() {
        let fs = FakeFs::new(&[], &[]);
        let mut out = Vec::new();
        let err = run(&mut out, &fs, &["missing.txt".into(), "b.txt".into()]).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn wrong_arg_count_errors() {
        let fs = FakeFs::new(&[], &[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &fs, &["only_one".into()]).is_err());
    }
}
