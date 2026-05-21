pub trait Env {
    fn vars(&self) -> Vec<(String, String)>;
    fn var(&self, key: &str) -> Option<String>;
}

pub struct SystemEnv;

impl Env for SystemEnv {
    fn vars(&self) -> Vec<(String, String)> {
        std::env::vars().collect()
    }
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}
