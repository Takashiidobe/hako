use std::io::{self, Write};
use std::time::Duration;

use crate::deps::Sleeper;

pub fn run(_out: &mut impl Write, sleeper: &impl Sleeper, args: &[String]) -> io::Result<()> {
    if args.len() != 1 {
        return Err(io::Error::other("usage: sleep <seconds>"));
    }

    let secs = args[0]
        .parse::<u64>()
        .map_err(|_| io::Error::other("seconds must be a non-negative integer"))?;
    sleeper.sleep(Duration::from_secs(secs));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::FakeSleeper;

    #[test]
    fn sleeps_for_seconds() {
        let sleeper = FakeSleeper::new();
        let mut out = Vec::new();
        run(&mut out, &sleeper, &["5".into()]).unwrap();
        assert_eq!(*sleeper.0.borrow(), vec![Duration::from_secs(5)]);
        assert!(out.is_empty());
    }

    #[test]
    fn zero_seconds_is_allowed() {
        let sleeper = FakeSleeper::new();
        let mut out = Vec::new();
        run(&mut out, &sleeper, &["0".into()]).unwrap();
        assert_eq!(*sleeper.0.borrow(), vec![Duration::from_secs(0)]);
    }

    #[test]
    fn requires_one_arg() {
        let sleeper = FakeSleeper::new();
        let mut out = Vec::new();
        assert!(run(&mut out, &sleeper, &[]).is_err());
        assert!(sleeper.0.borrow().is_empty());
    }

    #[test]
    fn rejects_invalid_seconds() {
        let sleeper = FakeSleeper::new();
        let mut out = Vec::new();
        assert!(run(&mut out, &sleeper, &["1.5".into()]).is_err());
        assert!(run(&mut out, &sleeper, &["-1".into()]).is_err());
        assert!(sleeper.0.borrow().is_empty());
    }
}
