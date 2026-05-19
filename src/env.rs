use std::io::{self, Write};

use crate::deps::Env;

pub fn run(out: &mut impl Write, env: &impl Env, args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        let mut vars = env.vars();
        vars.sort();
        for (k, v) in vars {
            writeln!(out, "{k}={v}")?;
        }
    } else {
        let mut missing = false;
        for key in args {
            match env.var(key) {
                Some(v) => writeln!(out, "{v}")?,
                None => {
                    eprintln!("{key}: not set");
                    missing = true;
                }
            }
        }
        if missing {
            return Err(io::Error::other("one or more variables not set"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::FakeEnv;

    #[test]
    fn no_args_prints_all_sorted() {
        let env = FakeEnv::new(&[("ZOO", "z"), ("AAA", "a")]);
        let mut out = Vec::new();
        run(&mut out, &env, &[]).unwrap();
        assert_eq!(out, b"AAA=a\nZOO=z\n");
    }

    #[test]
    fn args_print_values() {
        let env = FakeEnv::new(&[("HOME", "/root"), ("PATH", "/bin")]);
        let mut out = Vec::new();
        run(&mut out, &env, &["HOME".into()]).unwrap();
        assert_eq!(out, b"/root\n");
    }

    #[test]
    fn missing_var_errors() {
        let env = FakeEnv::new(&[]);
        let mut out = Vec::new();
        assert!(run(&mut out, &env, &["NOPE".into()]).is_err());
    }
}
