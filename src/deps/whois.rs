pub trait Whois {
    fn query(&self, server: &str, query: &str) -> std::io::Result<String>;
}

pub struct TcpWhois;

impl Whois for TcpWhois {
    fn query(&self, server: &str, query: &str) -> std::io::Result<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let mut stream = TcpStream::connect((server, 43u16))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        write!(stream, "{query}\r\n")?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }
}
