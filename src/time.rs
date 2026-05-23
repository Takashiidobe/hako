use std::io::{self, Write};
use std::time::UNIX_EPOCH;

use crate::deps::Clock;

pub fn run(out: &mut impl Write, clock: &impl Clock) -> io::Result<()> {
    let secs = clock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("clock is before Unix epoch"))?
        .as_secs();
    let (h, m, s) = (secs % 86400 / 3600, secs % 3600 / 60, secs % 60);
    writeln!(out, "{:02}:{:02}:{:02} UTC", h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Clock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0)
        }
    }

    #[test]
    fn midnight() {
        let mut buf = Vec::new();
        run(&mut buf, &FixedClock(0)).unwrap();
        assert_eq!(buf, b"00:00:00 UTC\n");
    }

    #[test]
    fn noon() {
        let mut buf = Vec::new();
        run(&mut buf, &FixedClock(43200)).unwrap();
        assert_eq!(buf, b"12:00:00 UTC\n");
    }
}
