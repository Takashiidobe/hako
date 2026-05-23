use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::deps::{DirFs, Dns, Env, Fs, HopResult, Icmp, Net, Probe, Sleeper};

pub struct FakeDns(pub Vec<Ipv4Addr>);

impl Dns for FakeDns {
    fn lookup_a(&self, _domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        Ok(self.0.clone())
    }

    fn lookup_ptr(&self, _addr: &Ipv4Addr) -> std::io::Result<Vec<String>> {
        Ok(vec![])
    }
}

pub struct FailDns;

impl Dns for FailDns {
    fn lookup_a(&self, _domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        Err(std::io::Error::other("timeout"))
    }

    fn lookup_ptr(&self, _addr: &Ipv4Addr) -> std::io::Result<Vec<String>> {
        Err(std::io::Error::other("timeout"))
    }
}

pub struct FakePtrDns(pub Vec<String>);

impl Dns for FakePtrDns {
    fn lookup_a(&self, _domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        Ok(vec![])
    }

    fn lookup_ptr(&self, _addr: &Ipv4Addr) -> std::io::Result<Vec<String>> {
        Ok(self.0.clone())
    }
}

pub struct FakeNet(pub Vec<u8>);

impl Net for FakeNet {
    fn request(&self, _method: &str, _url: &str, _body: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

pub struct FailNet;

impl Net for FailNet {
    fn request(&self, _method: &str, _url: &str, _body: &[u8]) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::other("connection refused"))
    }
}

pub struct FakeIcmp(pub Duration);

impl Icmp for FakeIcmp {
    fn send_ping(&self, _: Ipv4Addr, _: u16, _: &[u8]) -> std::io::Result<Duration> {
        Ok(self.0)
    }
}

pub struct FailIcmp;

impl Icmp for FailIcmp {
    fn send_ping(&self, _: Ipv4Addr, _: u16, _: &[u8]) -> std::io::Result<Duration> {
        Err(std::io::Error::other("timeout"))
    }
}

pub struct FakeEnv(pub Vec<(String, String)>);

impl FakeEnv {
    pub fn new(vars: &[(&str, &str)]) -> Self {
        Self(
            vars.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl Env for FakeEnv {
    fn vars(&self) -> Vec<(String, String)> {
        self.0.clone()
    }
    fn var(&self, key: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

pub struct FakeSleeper(pub RefCell<Vec<Duration>>);

impl FakeSleeper {
    pub fn new() -> Self {
        Self(RefCell::new(Vec::new()))
    }
}

impl Sleeper for FakeSleeper {
    fn sleep(&self, duration: Duration) {
        self.0.borrow_mut().push(duration);
    }
}

pub struct FakeFs {
    pub files: RefCell<HashMap<String, Vec<u8>>>,
    pub dirs: RefCell<HashSet<String>>,
}

impl FakeFs {
    pub fn new(files: &[(&str, &[u8])], dirs: &[&str]) -> Self {
        Self {
            files: RefCell::new(
                files
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_vec()))
                    .collect(),
            ),
            dirs: RefCell::new(dirs.iter().map(|d| d.to_string()).collect()),
        }
    }

    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.borrow().get(path).cloned()
    }

    pub fn has_dir(&self, path: &str) -> bool {
        self.dirs.borrow().contains(path)
    }
}

impl Fs for FakeFs {
    fn read(&self, path: &str) -> std::io::Result<String> {
        self.read_bytes(path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    fn write(&self, path: &str, content: &str) -> std::io::Result<()> {
        self.write_bytes(path, content.as_bytes())
    }

    fn is_file(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path)
    }
}

impl DirFs for FakeFs {
    fn read_bytes(&self, path: &str) -> std::io::Result<Vec<u8>> {
        self.files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| std::io::Error::other(format!("{path}: not found")))
    }

    fn write_bytes(&self, path: &str, content: &[u8]) -> std::io::Result<()> {
        self.files
            .borrow_mut()
            .insert(path.to_string(), content.to_vec());
        Ok(())
    }

    fn create_dir_all(&self, path: &str) -> std::io::Result<()> {
        use std::path::{Component, Path, PathBuf};
        let mut current = PathBuf::new();
        for component in Path::new(path).components() {
            if let Component::Normal(seg) = component {
                current.push(seg);
                self.dirs
                    .borrow_mut()
                    .insert(current.to_string_lossy().into_owned());
            }
        }
        Ok(())
    }

    fn is_dir(&self, path: &str) -> bool {
        self.has_dir(path)
    }

    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
        let prefix = format!("{path}/");
        let mut entries: Vec<String> = self
            .files
            .borrow()
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .filter_map(|k| k.get(prefix.len()..).map(str::to_string))
            .collect();
        entries.sort();
        Ok(entries)
    }
}

pub struct FakeProbe(pub RefCell<std::collections::VecDeque<HopResult>>);

impl FakeProbe {
    pub fn new(results: Vec<HopResult>) -> Self {
        Self(RefCell::new(results.into()))
    }
}

impl Probe for FakeProbe {
    fn probe(
        &self,
        _dest: std::net::Ipv4Addr,
        _ttl: u8,
        _seq: u16,
        _payload: &[u8],
    ) -> std::io::Result<HopResult> {
        self.0
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| std::io::Error::other("FakeProbe: no more results"))
    }
}
