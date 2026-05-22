pub trait Icmp {
    fn send_ping(
        &self,
        dest: std::net::Ipv4Addr,
        seq: u16,
        payload: &[u8],
    ) -> std::io::Result<std::time::Duration>;
}

pub struct SystemIcmp;

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_echo(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 8 + payload.len()];
    pkt[0] = 8; // echo request
    let [sh, sl] = seq.to_be_bytes();
    pkt[6] = sh;
    pkt[7] = sl;
    pkt[8..].copy_from_slice(payload);
    let ck = icmp_checksum(&pkt);
    pkt[2] = (ck >> 8) as u8;
    pkt[3] = ck as u8;
    pkt
}

#[cfg(unix)]
impl Icmp for SystemIcmp {
    fn send_ping(
        &self,
        dest: std::net::Ipv4Addr,
        seq: u16,
        payload: &[u8],
    ) -> std::io::Result<std::time::Duration> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::mem::MaybeUninit;
        use std::net::SocketAddrV4;
        use std::time::{Duration, Instant};

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))?;

        let pkt = build_icmp_echo(seq, payload);
        let addr: socket2::SockAddr = SocketAddrV4::new(dest, 0).into();

        let t0 = Instant::now();
        sock.send_to(&pkt, &addr)?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 256];
        let (n, _) = sock.recv_from(&mut buf)?;
        let rtt = t0.elapsed();

        // DGRAM ICMP: kernel strips IP header, data starts at ICMP header
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if data.len() < 8 {
            return Err(std::io::Error::other("ICMP response too short"));
        }
        if data[0] != 0 {
            return Err(std::io::Error::other(format!(
                "unexpected ICMP type {}",
                data[0]
            )));
        }

        Ok(rtt)
    }
}

#[cfg(target_os = "windows")]
impl Icmp for SystemIcmp {
    fn send_ping(
        &self,
        dest: std::net::Ipv4Addr,
        seq: u16,
        payload: &[u8],
    ) -> std::io::Result<std::time::Duration> {
        use std::ptr;
        use std::time::Duration;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
        };

        let _ = seq; // Windows API doesn't expose seq; RTT comes from reply struct
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let dest_addr = u32::from_ne_bytes(dest.octets());
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
        let mut reply_buf = vec![0u8; reply_size];

        let ret = unsafe {
            IcmpSendEcho(
                handle,
                dest_addr,
                payload.as_ptr() as *mut _,
                payload.len() as u16,
                ptr::null_mut(),
                reply_buf.as_mut_ptr() as *mut _,
                reply_size as u32,
                5000,
            )
        };
        unsafe { IcmpCloseHandle(handle) };

        if ret == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let reply = unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };
        Ok(Duration::from_millis(reply.RoundTripTime as u64))
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
impl Icmp for SystemIcmp {
    fn send_ping(
        &self,
        _dest: std::net::Ipv4Addr,
        _seq: u16,
        _payload: &[u8],
    ) -> std::io::Result<std::time::Duration> {
        Err(std::io::Error::other("ping not supported on this platform"))
    }
}
