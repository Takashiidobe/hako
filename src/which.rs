use std::io::{self, Write};

use crate::deps::{Env, Fs};

pub fn run(out: &mut impl Write, env: &impl Env, fs: &impl Fs, args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        return Err(io::Error::other("usage: which <command>..."));
    }

    let path_val = env.var("PATH").unwrap_or_default();
    let mut any_missing = false;

    for name in args {
        let found = std::env::split_paths(&path_val)
            .map(|dir| dir.join(name).to_string_lossy().into_owned())
            .find(|candidate| fs.is_file(candidate));

        match found {
            Some(path) => writeln!(out, "{path}")?,
            None => {
                eprintln!("{name}: not found");
                any_missing = true;
            }
        }
    }

    if any_missing {
        Err(io::Error::other("one or more commands not found"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FakeEnv, FakeFs};

    #[test]
    fn finds_command_in_path() {
        let env = FakeEnv::new(&[("PATH", "/usr/bin:/bin")]);
        let fs = FakeFs::new(&[("/usr/bin/ls", b"")], &[]);
        let mut out = Vec::new();
        run(&mut out, &env, &fs, &["ls".into()]).unwrap();
        assert_eq!(out, b"/usr/bin/ls\n");
    }

    #[test]
    fn finds_first_match_in_path() {
        let env = FakeEnv::new(&[("PATH", "/usr/local/bin:/usr/bin")]);
        let fs = FakeFs::new(&[("/usr/local/bin/grep", b""), ("/usr/bin/grep", b"")], &[]);
        let mut out = Vec::new();
        run(&mut out, &env, &fs, &["grep".into()]).unwrap();
        assert_eq!(out, b"/usr/local/bin/grep\n");
    }

    #[test]
    fn missing_command_errors() {
        let env = FakeEnv::new(&[("PATH", "/bin")]);
        let fs = FakeFs::new(&[], &[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &env, &fs, &["nope".into()]).is_err());
    }

    #[test]
    fn no_args_errors() {
        let env = FakeEnv::new(&[("PATH", "/bin")]);
        let fs = FakeFs::new(&[], &[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &env, &fs, &[]).is_err());
    }

    #[test]
    fn multiple_commands() {
        let env = FakeEnv::new(&[("PATH", "/bin")]);
        let fs = FakeFs::new(&[("/bin/ls", b""), ("/bin/cat", b"")], &[]);
        let mut out = Vec::new();
        run(&mut out, &env, &fs, &["ls".into(), "cat".into()]).unwrap();
        assert_eq!(out, b"/bin/ls\n/bin/cat\n");
    }
}
