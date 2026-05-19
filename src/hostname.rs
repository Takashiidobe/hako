use std::io::{self, Write};

use crate::deps::Hostname;

pub fn run(out: &mut impl Write, sys: &impl Hostname) -> io::Result<()> {
    let name = sys.hostname()?;
    writeln!(out, "{name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Hostname;

    struct FakeHostname(&'static str);
    impl Hostname for FakeHostname {
        fn hostname(&self) -> io::Result<String> {
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn prints_hostname() {
        let mut out = Vec::new();
        run(&mut out, &FakeHostname("mybox")).unwrap();
        assert_eq!(out, b"mybox\n");
    }
}
