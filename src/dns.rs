use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::rr::Name;
use smol::future::FutureExt;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpStream, UdpSocket};

pub const UDP_TIMEOUT: Duration = Duration::from_secs(5);
pub const TCP_TIMEOUT: Duration = Duration::from_secs(5);
pub const UDP_MAX_PACKET_SIZE: usize = 4096;

#[derive(Clone, Copy)]
pub enum Transport {
  Udp,
  Tcp,
}

pub async fn resolve(
  addresses: &[SocketAddr],
  query_bytes: &[u8],
  qname: &Name,
  transport: Transport,
  log_enabled: bool,
) -> Option<Vec<u8>> {
  for addr in addresses.iter().copied() {
    let resp = match transport {
      Transport::Udp => udp_query(addr, query_bytes, qname, log_enabled).await,
      Transport::Tcp => tcp_query(addr, query_bytes, qname, log_enabled).await,
    };
    if let Some(resp) = resp {
      return Some(resp);
    }
  }
  None
}

async fn udp_query(addr: SocketAddr, query: &[u8], qname: &Name, log_enabled: bool) -> Option<Vec<u8>> {
  let local = if addr.is_ipv4() {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
  } else {
    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
  };

  let socket = UdpSocket::bind(local).await.ok()?;

  let send_recv = async {
    socket.send_to(query, addr).await?;
    let mut buf = [0u8; UDP_MAX_PACKET_SIZE];
    let (n, _) = socket.recv_from(&mut buf).await?;
    Ok::<_, io::Error>(buf[..n].to_vec())
  };

  let result = send_recv
    .or(async {
      smol::Timer::after(UDP_TIMEOUT).await;
      Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
    })
    .await;

  match result {
    Ok(resp) => Some(resp),
    Err(e) => {
      if log_enabled {
        if e.kind() == io::ErrorKind::TimedOut {
          eprintln!("upstream timeout: {addr:?}, {qname}");
        } else {
          eprintln!("upstream error: {addr:?}, {qname}: {e}");
        }
      }
      None
    }
  }
}

async fn tcp_query(addr: SocketAddr, query: &[u8], qname: &Name, log_enabled: bool) -> Option<Vec<u8>> {
  let connect = async {
    let mut stream = TcpStream::connect(addr).await?;

    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok::<_, io::Error>(resp)
  };

  let result = connect
    .or(async {
      smol::Timer::after(TCP_TIMEOUT).await;
      Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
    })
    .await;

  match result {
    Ok(resp) => Some(resp),
    Err(e) => {
      if log_enabled {
        if e.kind() == io::ErrorKind::TimedOut {
          eprintln!("upstream timeout: {addr:?}, {qname}");
        } else {
          eprintln!("upstream error: {addr:?}, {qname}: {e}");
        }
      }
      None
    }
  }
}
