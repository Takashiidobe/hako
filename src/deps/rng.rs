use std::time::SystemTime;

pub trait Rng {
    fn next_u64(&mut self) -> u64;
}

pub struct SystemRng {
    state: u64,
}

impl SystemRng {
    pub fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64;
        Self {
            state: seed ^ 0x9e3779b97f4a7c15,
        }
    }
}

impl Rng for SystemRng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}
