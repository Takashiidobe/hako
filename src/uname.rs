use std::io::{self, Write};

use crate::deps::Uname;

pub fn run(out: &mut impl Write, sys: &impl Uname, args: &[String]) -> io::Result<()> {
    // flags: -s sysname, -n nodename, -r release, -v version, -m machine, -a all
    // default (no flags): sysname only, matching real uname behaviour
    let info = sys.uname()?;

    let all = args.iter().any(|a| a == "-a");
    let show_s = all || args.iter().any(|a| a == "-s") || args.is_empty();
    let show_n = all || args.iter().any(|a| a == "-n");
    let show_r = all || args.iter().any(|a| a == "-r");
    let show_v = all || args.iter().any(|a| a == "-v");
    let show_m = all || args.iter().any(|a| a == "-m");

    let mut parts = Vec::new();
    if show_s {
        parts.push(info.sysname.as_str());
    }
    if show_n {
        parts.push(info.nodename.as_str());
    }
    if show_r {
        parts.push(info.release.as_str());
    }
    if show_v {
        parts.push(info.version.as_str());
    }
    if show_m {
        parts.push(info.machine.as_str());
    }

    writeln!(out, "{}", parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Uname;
    use crate::deps::system::UnameInfo;

    struct FakeUname;
    impl Uname for FakeUname {
        fn uname(&self) -> io::Result<UnameInfo> {
            Ok(UnameInfo {
                sysname: "Linux".into(),
                nodename: "mybox".into(),
                release: "6.1.0".into(),
                version: "#1 SMP".into(),
                machine: "x86_64".into(),
            })
        }
    }

    #[test]
    fn default_prints_sysname() {
        let mut out = Vec::new();
        run(&mut out, &FakeUname, &[]).unwrap();
        assert_eq!(out, b"Linux\n");
    }

    #[test]
    fn dash_a_prints_all() {
        let mut out = Vec::new();
        run(&mut out, &FakeUname, &["-a".into()]).unwrap();
        assert_eq!(out, b"Linux mybox 6.1.0 #1 SMP x86_64\n");
    }

    #[test]
    fn dash_r_prints_release() {
        let mut out = Vec::new();
        run(&mut out, &FakeUname, &["-r".into()]).unwrap();
        assert_eq!(out, b"6.1.0\n");
    }

    #[test]
    fn multiple_flags() {
        let mut out = Vec::new();
        run(&mut out, &FakeUname, &["-s".into(), "-m".into()]).unwrap();
        assert_eq!(out, b"Linux x86_64\n");
    }
}
