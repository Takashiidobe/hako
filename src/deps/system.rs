pub struct UnameInfo {
    pub sysname: String,
    pub nodename: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

pub trait Hostname {
    fn hostname(&self) -> std::io::Result<String>;
}

pub trait Uname {
    fn uname(&self) -> std::io::Result<UnameInfo>;
}

pub struct SystemInfo;

#[cfg(unix)]
impl Hostname for SystemInfo {
    fn hostname(&self) -> std::io::Result<String> {
        nix::unistd::gethostname()
            .map(|n| n.to_string_lossy().into_owned())
            .map_err(std::io::Error::from)
    }
}

#[cfg(unix)]
impl Uname for SystemInfo {
    fn uname(&self) -> std::io::Result<UnameInfo> {
        let u = nix::sys::utsname::uname().map_err(std::io::Error::from)?;
        Ok(UnameInfo {
            sysname: u.sysname().to_string_lossy().into_owned(),
            nodename: u.nodename().to_string_lossy().into_owned(),
            release: u.release().to_string_lossy().into_owned(),
            version: u.version().to_string_lossy().into_owned(),
            machine: u.machine().to_string_lossy().into_owned(),
        })
    }
}
