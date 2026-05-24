use std::net::Ipv4Addr;
use std::time::SystemTime;

pub trait Dns {
    fn lookup_a(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>>;
    fn lookup_ptr(&self, addr: &Ipv4Addr) -> std::io::Result<Vec<String>>;
    fn lookup_aaaa(&self, domain: &str) -> std::io::Result<Vec<String>>;
    fn lookup_mx(&self, domain: &str) -> std::io::Result<Vec<String>>;
    fn lookup_txt(&self, domain: &str) -> std::io::Result<Vec<String>>;
    fn lookup_ns(&self, domain: &str) -> std::io::Result<Vec<String>>;
    fn lookup_cname(&self, domain: &str) -> std::io::Result<Vec<String>>;
}

pub struct UdpDns {
    pub nameserver: Ipv4Addr,
}

impl Default for UdpDns {
    fn default() -> Self {
        Self {
            nameserver: Ipv4Addr::new(8, 8, 8, 8),
        }
    }
}

impl Dns for UdpDns {
    fn lookup_a(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        let buf = self.query(domain, 1)?;
        parse_a_records(&buf)
    }

    fn lookup_ptr(&self, addr: &Ipv4Addr) -> std::io::Result<Vec<String>> {
        let oct = addr.octets();
        let arpa = format!("{}.{}.{}.{}.in-addr.arpa", oct[3], oct[2], oct[1], oct[0]);
        let buf = self.query(&arpa, 12)?;
        parse_ptr_records(&buf)
    }

    fn lookup_aaaa(&self, domain: &str) -> std::io::Result<Vec<String>> {
        let buf = self.query(domain, 28)?;
        parse_aaaa_records(&buf)
    }

    fn lookup_mx(&self, domain: &str) -> std::io::Result<Vec<String>> {
        let buf = self.query(domain, 15)?;
        parse_mx_records(&buf)
    }

    fn lookup_txt(&self, domain: &str) -> std::io::Result<Vec<String>> {
        let buf = self.query(domain, 16)?;
        parse_txt_records(&buf)
    }

    fn lookup_ns(&self, domain: &str) -> std::io::Result<Vec<String>> {
        let buf = self.query(domain, 2)?;
        parse_name_records(&buf, 2)
    }

    fn lookup_cname(&self, domain: &str) -> std::io::Result<Vec<String>> {
        let buf = self.query(domain, 5)?;
        parse_name_records(&buf, 5)
    }
}

impl UdpDns {
    fn query(&self, domain: &str, qtype: u16) -> std::io::Result<Vec<u8>> {
        use std::net::{SocketAddr, UdpSocket};

        let id = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()) as u16;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(
            &build_query(domain, id, qtype),
            SocketAddr::from((self.nameserver, 53)),
        )?;

        let mut buf = [0u8; 512];
        let (n, _) = socket.recv_from(&mut buf)?;
        let raw = buf
            .get(..n)
            .ok_or_else(|| std::io::Error::other("invalid DNS response length"))?;

        if raw.len() < 12 {
            return Err(std::io::Error::other("response too short"));
        }
        if read_u16(raw, 0)? != id {
            return Err(std::io::Error::other("ID mismatch"));
        }
        let rcode = read_u16(raw, 2)? & 0xf;
        if rcode != 0 {
            return Err(std::io::Error::other(format!("DNS rcode {rcode}")));
        }

        Ok(raw.to_vec())
    }
}

fn build_query(domain: &str, id: u16, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
    for label in domain.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    buf
}

fn read_u16(buf: &[u8], pos: usize) -> std::io::Result<u16> {
    let bytes: [u8; 2] = buf
        .get(pos..pos + 2)
        .ok_or_else(|| std::io::Error::other("truncated DNS response"))?
        .try_into()
        .map_err(|_| std::io::Error::other("truncated DNS response"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        } else if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

// Reads a DNS name at `pos`, following compression pointers. Returns the name and
// the position after the name field (not after the pointer target).
fn read_name(buf: &[u8], pos: usize) -> std::io::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cur = pos;
    let mut end = None; // position after the original name field

    loop {
        let len = *buf
            .get(cur)
            .ok_or_else(|| std::io::Error::other("truncated name"))? as usize;

        if len == 0 {
            if end.is_none() {
                end = Some(cur + 1);
            }
            break;
        } else if len & 0xc0 == 0xc0 {
            // compression pointer
            let ptr = (len & 0x3f) << 8
                | *buf
                    .get(cur + 1)
                    .ok_or_else(|| std::io::Error::other("truncated pointer"))?
                    as usize;
            if end.is_none() {
                end = Some(cur + 2);
            }
            cur = ptr;
        } else {
            cur += 1;
            let label = buf
                .get(cur..cur + len)
                .ok_or_else(|| std::io::Error::other("truncated label"))?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            cur += len;
        }
    }

    Ok((labels.join("."), end.unwrap_or(cur)))
}

fn skip_questions(buf: &[u8], qdcount: usize) -> std::io::Result<usize> {
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed question"))?;
        pos += 4; // QTYPE + QCLASS
    }
    Ok(pos)
}

fn parse_a_records(buf: &[u8]) -> std::io::Result<Vec<Ipv4Addr>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 1 && rdlen == 4 {
            let octets: [u8; 4] = buf
                .get(pos..pos + 4)
                .ok_or_else(|| std::io::Error::other("truncated A record"))?
                .try_into()
                .map_err(|_| std::io::Error::other("truncated A record"))?;
            addrs.push(Ipv4Addr::from(octets));
        }
        pos += rdlen;
    }
    Ok(addrs)
}

fn parse_aaaa_records(buf: &[u8]) -> std::io::Result<Vec<String>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 28 && rdlen == 16 {
            let octets: [u8; 16] = buf[pos..pos + 16]
                .try_into()
                .map_err(|_| std::io::Error::other("truncated AAAA record"))?;
            addrs.push(std::net::Ipv6Addr::from(octets).to_string());
        }
        pos += rdlen;
    }
    Ok(addrs)
}

fn parse_mx_records(buf: &[u8]) -> std::io::Result<Vec<String>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;
    let mut records = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 15 {
            let pref = read_u16(buf, pos)?;
            let (exchange, _) = read_name(buf, pos + 2)?;
            records.push(format!("{pref} {exchange}"));
        }
        pos += rdlen;
    }
    Ok(records)
}

fn parse_txt_records(buf: &[u8]) -> std::io::Result<Vec<String>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;
    let mut records = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 16 {
            // TXT rdata: one or more length-prefixed character strings
            let mut txt = String::new();
            let end = pos + rdlen;
            let mut cur = pos;
            while cur < end {
                let len =
                    *buf.get(cur).ok_or_else(|| std::io::Error::other("truncated TXT"))? as usize;
                cur += 1;
                let s = buf
                    .get(cur..cur + len)
                    .ok_or_else(|| std::io::Error::other("truncated TXT data"))?;
                txt.push_str(&String::from_utf8_lossy(s));
                cur += len;
            }
            records.push(txt);
        }
        pos += rdlen;
    }
    Ok(records)
}

// NS (qtype 2) and CNAME (qtype 5) both store a single domain name in rdata.
fn parse_name_records(buf: &[u8], expected_type: u16) -> std::io::Result<Vec<String>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;
    let mut names = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == expected_type {
            let (name, _) = read_name(buf, pos)?;
            names.push(name);
        }
        pos += rdlen;
    }
    Ok(names)
}

fn parse_ptr_records(buf: &[u8]) -> std::io::Result<Vec<String>> {
    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;
    let mut pos = skip_questions(buf, qdcount)?;

    let mut names = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = read_u16(buf, pos)?;
        let rdlen = read_u16(buf, pos + 8)? as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 12 {
            let (name, _) = read_name(buf, pos)?;
            names.push(name);
        }
        pos += rdlen;
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_domain() {
        let q = build_query("example.com", 0x1234, 1);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(&q[24..], &[0, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parse_a_records_single() {
        let mut pkt: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // flags
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, 0x00, 0x00, // NS/AR=0
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01, // answer: compressed name, A, IN, TTL=300, RDLEN=4, 1.2.3.4
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 1, 2, 3, 4,
        ];
        let addrs = parse_a_records(&pkt).unwrap();
        assert_eq!(addrs, vec![Ipv4Addr::new(1, 2, 3, 4)]);

        pkt[7] = 0; // ANCOUNT=0
        let addrs = parse_a_records(&pkt).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn parse_ptr_record() {
        // PTR response for 4.3.2.1.in-addr.arpa -> "host.example.com"
        // question name bytes
        let qname: &[u8] = &[
            1, b'4', 1, b'3', 1, b'2', 1, b'1', 7, b'i', b'n', b'-', b'a', b'd', b'd', b'r', 4,
            b'a', b'r', b'p', b'a', 0,
        ];
        // PTR rdata: "host.example.com"
        let rdata: &[u8] = &[
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0,
        ];
        let rdlen = rdata.len() as u16;

        let mut pkt: Vec<u8> = vec![
            0xab, 0xcd, // ID
            0x81, 0x80, // flags
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(qname);
        pkt.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // QTYPE=PTR, QCLASS=IN
        pkt.extend_from_slice(&[0xc0, 0x0c]); // compressed name -> offset 12
        pkt.extend_from_slice(&[0x00, 0x0c]); // TYPE=PTR
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL=300
        pkt.extend_from_slice(&rdlen.to_be_bytes());
        pkt.extend_from_slice(rdata);

        let names = parse_ptr_records(&pkt).unwrap();
        assert_eq!(names, vec!["host.example.com"]);
    }

    #[test]
    fn parse_ptr_empty() {
        let qname: &[u8] = &[1, b'1', 0];
        let mut pkt: Vec<u8> = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend_from_slice(qname);
        pkt.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
        let names = parse_ptr_records(&pkt).unwrap();
        assert!(names.is_empty());
    }
}
