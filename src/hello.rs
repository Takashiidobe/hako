use std::io::{self, Write};

pub fn run(out: &mut impl Write, args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        writeln!(out, "hello")
    } else {
        writeln!(out, "hello {}", args.join(" and "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_args() {
        let mut buf = Vec::new();
        run(&mut buf, &[]).unwrap();
        assert_eq!(buf, b"hello\n");
    }

    #[test]
    fn one_arg() {
        let mut buf = Vec::new();
        run(&mut buf, &["alice".into()]).unwrap();
        assert_eq!(buf, b"hello alice\n");
    }

    #[test]
    fn multiple_args() {
        let mut buf = Vec::new();
        run(&mut buf, &["alice".into(), "bob".into()]).unwrap();
        assert_eq!(buf, b"hello alice and bob\n");
    }
}
