use std::io::{self, Write};

use crate::deps::Rng;

pub fn run(out: &mut impl Write, rng: &mut impl Rng) -> io::Result<()> {
    writeln!(out, "{}", rng.next_u64() % 100 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Rng;

    struct ConstRng(u64);

    impl Rng for ConstRng {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    #[test]
    fn in_range() {
        let mut buf = Vec::new();
        run(&mut buf, &mut ConstRng(42)).unwrap();
        assert_eq!(buf, b"43\n"); // 42 % 100 + 1
    }

    #[test]
    fn wraps_at_100() {
        let mut buf = Vec::new();
        run(&mut buf, &mut ConstRng(100)).unwrap();
        assert_eq!(buf, b"1\n");
    }
}
