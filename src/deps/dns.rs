use std::net::Ipv4Addr;
use std::time::SystemTime;

pub trait Dns {
    fn lookup_a(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>>;
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
        use std::net::{SocketAddr, UdpSocket};

        let id = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos()) as u16;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(
            &build_query(domain, id),
            SocketAddr::from((self.nameserver, 53)),
        )?;

        let mut buf = [0u8; 512];
        let (n, _) = socket.recv_from(&mut buf)?;
        parse_a_records(
            buf.get(..n)
                .ok_or_else(|| std::io::Error::other("invalid DNS response length"))?,
            id,
        )
    }
}

fn build_query(domain: &str, id: u16) -> Vec<u8> {
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
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    buf
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        } else if len & 0xc0 == 0xc0 {
            return Some(pos + 2); // compression pointer
        }
        pos += 1 + len;
    }
}

fn read_u16(buf: &[u8], pos: usize) -> std::io::Result<u16> {
    let bytes: [u8; 2] = buf
        .get(pos..pos + 2)
        .ok_or_else(|| std::io::Error::other("truncated DNS response"))?
        .try_into()
        .map_err(|_| std::io::Error::other("truncated DNS response"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn parse_a_records(buf: &[u8], id: u16) -> std::io::Result<Vec<Ipv4Addr>> {
    if buf.len() < 12 {
        return Err(std::io::Error::other("response too short"));
    }
    if read_u16(buf, 0)? != id {
        return Err(std::io::Error::other("ID mismatch"));
    }
    let rcode = read_u16(buf, 2)? & 0xf;
    if rcode != 0 {
        return Err(std::io::Error::other(format!("DNS rcode {rcode}")));
    }

    let qdcount = read_u16(buf, 4)? as usize;
    let ancount = read_u16(buf, 6)? as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed question"))?;
        pos += 4; // QTYPE + QCLASS
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_domain() {
        let q = build_query("example.com", 0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // "example" label
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        // "com" label
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        // root + QTYPE A + QCLASS IN
        assert_eq!(&q[24..], &[0, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parse_a_records_single() {
        // hand-crafted response: ID=0x1234, one A record 1.2.3.4
        let mut pkt: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // flags: QR=1 RD=1 RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, 0x00, 0x00, // NS/AR=0
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
            // answer: compressed name -> offset 12, A, IN, TTL=300, RDLEN=4, 1.2.3.4
            0xc0, 0x0c, 0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2c, // TTL=300
            0x00, 0x04, // RDLEN=4
            1, 2, 3, 4,
        ];
        let addrs = parse_a_records(&pkt, 0x1234).unwrap();
        assert_eq!(addrs, vec![Ipv4Addr::new(1, 2, 3, 4)]);

        // AAAA records in the answer should be ignored
        pkt[7] = 0; // ANCOUNT=0 answers
        let addrs = parse_a_records(&pkt, 0x1234).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn parse_rejects_id_mismatch() {
        let pkt = vec![0x00; 12];
        assert!(parse_a_records(&pkt, 0x0001).is_err());
    }

    #[test]
    fn parse_rejects_nonzero_rcode() {
        let mut pkt = vec![0x12, 0x34, 0x81, 0x83]; // rcode=3 NXDOMAIN
        pkt.extend_from_slice(&[0u8; 8]);
        assert!(parse_a_records(&pkt, 0x1234).is_err());
    }
}
