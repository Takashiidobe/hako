use std::time::{Duration, SystemTime};

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub trait Sleeper {
    fn sleep(&self, duration: Duration);
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

impl Sleeper for SystemClock {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
