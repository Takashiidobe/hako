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
    use crate::deps::Fs;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeFs {
        files: RefCell<HashMap<String, String>>,
    }

    impl FakeFs {
        fn new(files: &[(&str, &str)]) -> Self {
            Self {
                files: RefCell::new(
                    files
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
            }
        }

        fn get(&self, path: &str) -> Option<String> {
            self.files.borrow().get(path).cloned()
        }
    }

    impl Fs for FakeFs {
        fn read(&self, path: &str) -> io::Result<String> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::other(format!("{path}: no such file")))
        }

        fn write(&self, path: &str, content: &str) -> io::Result<()> {
            self.files
                .borrow_mut()
                .insert(path.to_string(), content.to_string());
            Ok(())
        }
    }

    #[test]
    fn copies_contents() {
        let fs = FakeFs::new(&[("a.txt", "hello")]);
        let mut out = Vec::new();
        run(&mut out, &fs, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert_eq!(fs.get("b.txt").as_deref(), Some("hello"));
    }

    #[test]
    fn overwrites_existing() {
        let fs = FakeFs::new(&[("a.txt", "new"), ("b.txt", "old")]);
        let mut out = Vec::new();
        run(&mut out, &fs, &["a.txt".into(), "b.txt".into()]).unwrap();
        assert_eq!(fs.get("b.txt").as_deref(), Some("new"));
    }

    #[test]
    fn missing_src_errors() {
        let fs = FakeFs::new(&[]);
        let mut out = Vec::new();
        let err = run(&mut out, &fs, &["missing.txt".into(), "b.txt".into()]).unwrap_err();
        assert!(err.to_string().contains("no such file"));
    }

    #[test]
    fn wrong_arg_count_errors() {
        let fs = FakeFs::new(&[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &fs, &["only_one".into()]).is_err());
    }
}
