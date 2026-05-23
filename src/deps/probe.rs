use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

pub enum HopResult {
    Reply {
        from: Ipv4Addr,
        rtt: Duration,
        /// true = Echo Reply (destination reached), false = Time Exceeded (intermediate hop)
        reached: bool,
    },
    Timeout,
}

pub trait Probe {
    fn probe(&self, dest: Ipv4Addr, ttl: u8, seq: u16, payload: &[u8]) -> io::Result<HopResult>;
}

pub struct SystemProbe;

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let pair: [u8; 2] = chunk.try_into().unwrap_or([0, 0]);
        sum += u16::from_be_bytes(pair) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += (*byte as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_echo(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.extend_from_slice(&[8, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    let ck = icmp_checksum(&pkt);
    let [hi, lo] = ck.to_be_bytes();
    pkt.splice(2..4, [hi, lo]);
    pkt
}

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    data.get(pos..pos + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
}

// ----- Linux -------------------------------------------------------------------
// Try SOCK_RAW first (needs CAP_NET_RAW / root).  On EPERM fall back to the
// unprivileged ping socket (SOCK_DGRAM + IPPROTO_ICMP) with IP_RECVERR so that
// Time-Exceeded errors are delivered to the error queue.

#[cfg(target_os = "linux")]
impl Probe for SystemProbe {
    fn probe(&self, dest: Ipv4Addr, ttl: u8, seq: u16, payload: &[u8]) -> io::Result<HopResult> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::SocketAddrV4;
        use std::time::Instant;

        let (sock, is_raw) = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => (s, true),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
                (s, false)
            }
            Err(e) => return Err(e),
        };

        sock.set_ttl_v4(ttl as u32)?;
        sock.set_nonblocking(true)?;

        if !is_raw {
            use nix::sys::socket::{setsockopt, sockopt::Ipv4RecvErr};
            setsockopt(&sock, Ipv4RecvErr, &true).map_err(io::Error::from)?;
        }

        let pkt = build_icmp_echo(seq, payload);
        let addr: socket2::SockAddr = SocketAddrV4::new(dest, 0).into();
        let t0 = Instant::now();
        sock.send_to(&pkt, &addr)?;

        poll_icmp(&sock, is_raw, dest, seq, t0)
    }
}

#[cfg(target_os = "linux")]
fn poll_icmp(
    sock: &socket2::Socket,
    is_raw: bool,
    dest: Ipv4Addr,
    seq: u16,
    t0: std::time::Instant,
) -> io::Result<HopResult> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd;
    use std::time::Instant;

    let deadline = t0 + Duration::from_secs(3);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(HopResult::Timeout);
        }

        let timeout_ms =
            u16::try_from(remaining.as_millis().min(u16::MAX as u128)).unwrap_or(u16::MAX);
        let mut pfds = [PollFd::new(
            sock.as_fd(),
            PollFlags::POLLIN | PollFlags::POLLERR,
        )];
        let ready = poll(&mut pfds, PollTimeout::from(timeout_ms)).map_err(io::Error::from)?;
        if ready == 0 {
            return Ok(HopResult::Timeout);
        }

        let revents = pfds[0].revents().unwrap_or(PollFlags::empty());
        let rtt = t0.elapsed();

        if revents.contains(PollFlags::POLLERR) && !is_raw {
            if let Some(hop) = recv_error_queue(sock, seq)? {
                return Ok(HopResult::Reply {
                    from: hop,
                    rtt,
                    reached: false,
                });
            }
            continue;
        }

        if revents.contains(PollFlags::POLLIN) {
            let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
            match sock.recv_from(&mut buf) {
                Ok((n, from_addr)) => {
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };

                    // RAW: full IP packet (skip 20-byte header); DGRAM: starts at ICMP header.
                    let icmp = if is_raw {
                        if data.len() < 28 {
                            continue;
                        }
                        data.get(20..).unwrap_or(&[])
                    } else {
                        if data.len() < 8 {
                            continue;
                        }
                        data
                    };

                    let from_ip = from_addr.as_socket_ipv4().map(|s| *s.ip()).unwrap_or(dest);

                    match icmp.first().copied() {
                        Some(0) => {
                            let Some(reply_seq) = read_u16(icmp, 6) else {
                                continue;
                            };
                            if reply_seq != seq {
                                continue;
                            }
                            return Ok(HopResult::Reply {
                                from: from_ip,
                                rtt,
                                reached: true,
                            });
                        }
                        Some(11) if is_raw => {
                            if icmp.len() < 8 + 20 + 8 {
                                continue;
                            }
                            let Some(inner) = icmp.get(8 + 20..) else {
                                continue;
                            };
                            let Some(inner_seq) = read_u16(inner, 6) else {
                                continue;
                            };
                            if inner_seq != seq {
                                continue;
                            }
                            return Ok(HopResult::Reply {
                                from: from_ip,
                                rtt,
                                reached: false,
                            });
                        }
                        _ => continue,
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Read one message from the error queue and return the router's address if it
/// is an ICMP Time-Exceeded for our probe sequence number.
#[cfg(target_os = "linux")]
fn recv_error_queue(sock: &socket2::Socket, seq: u16) -> io::Result<Option<Ipv4Addr>> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg};
    use std::io::IoSliceMut;
    use std::os::unix::io::AsRawFd;

    let mut payload_buf = [0u8; 256];
    // 256 bytes is ample for sock_extended_err + sockaddr_in + CMSG overhead.
    let mut cmsg_buf = [0u8; 256];
    let mut iov = [IoSliceMut::new(&mut payload_buf)];

    let msg = recvmsg::<SockaddrIn>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_ERRQUEUE,
    );

    let msg = match msg {
        Ok(m) => m,
        Err(nix::errno::Errno::EAGAIN) => return Ok(None),
        Err(e) => return Err(io::Error::from(e)),
    };

    // The payload on the error queue is the original ICMP echo we sent.
    // Read seq through iovs() to avoid a conflicting immutable borrow of payload_buf.
    let pkt_seq = msg
        .iovs()
        .next()
        .filter(|s| s.len() >= 8)
        .and_then(|s| read_u16(s, 6));
    if pkt_seq != Some(seq) {
        return Ok(None);
    }

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::Ipv4RecvErr(ee, Some(offender)) = cmsg {
            // ee_type 11 = Time Exceeded
            if ee.ee_type == 11 {
                let addr = Ipv4Addr::from(u32::from_be(offender.sin_addr.s_addr));
                return Ok(Some(addr));
            }
        }
    }

    Ok(None)
}

// ----- non-Linux Unix ----------------------------------------------------------
// Raw socket only; requires CAP_NET_RAW or root.

#[cfg(all(unix, not(target_os = "linux")))]
impl Probe for SystemProbe {
    fn probe(&self, dest: Ipv4Addr, ttl: u8, seq: u16, payload: &[u8]) -> io::Result<HopResult> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::mem::MaybeUninit;
        use std::net::SocketAddrV4;
        use std::time::Instant;

        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        sock.set_ttl_v4(ttl as u32)?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;

        let pkt = build_icmp_echo(seq, payload);
        let addr: socket2::SockAddr = SocketAddrV4::new(dest, 0).into();
        let t0 = Instant::now();
        sock.send_to(&pkt, &addr)?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
        loop {
            match sock.recv_from(&mut buf) {
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(HopResult::Timeout);
                }
                Err(e) => return Err(e),
                Ok((n, from)) => {
                    let rtt = t0.elapsed();
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    if data.len() < 28 {
                        continue;
                    }
                    let icmp = &data[20..];
                    let Some(from_ip) = from.as_socket_ipv4().map(|s| *s.ip()) else {
                        continue;
                    };
                    match icmp[0] {
                        0 => {
                            let reply_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                            if reply_seq != seq {
                                continue;
                            }
                            return Ok(HopResult::Reply {
                                from: from_ip,
                                rtt,
                                reached: true,
                            });
                        }
                        11 => {
                            if icmp.len() < 8 + 20 + 8 {
                                continue;
                            }
                            let inner = &icmp[8 + 20..];
                            let inner_seq = u16::from_be_bytes([inner[6], inner[7]]);
                            if inner_seq != seq {
                                continue;
                            }
                            return Ok(HopResult::Reply {
                                from: from_ip,
                                rtt,
                                reached: false,
                            });
                        }
                        _ => continue,
                    }
                }
            }
        }
    }
}

// ----- Windows ----------------------------------------------------------------

#[cfg(target_os = "windows")]
impl Probe for SystemProbe {
    fn probe(
        &self,
        _dest: Ipv4Addr,
        _ttl: u8,
        _seq: u16,
        _payload: &[u8],
    ) -> io::Result<HopResult> {
        Err(io::Error::other("traceroute not yet supported on Windows"))
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
impl Probe for SystemProbe {
    fn probe(
        &self,
        _dest: Ipv4Addr,
        _ttl: u8,
        _seq: u16,
        _payload: &[u8],
    ) -> io::Result<HopResult> {
        Err(io::Error::other(
            "traceroute not supported on this platform",
        ))
    }
}
