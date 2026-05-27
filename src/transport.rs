use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context;
use async_io::Timer;
use async_net::{TcpStream, UdpSocket};
use futures_lite::FutureExt;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use hickory_proto::rr::Name;

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
) -> anyhow::Result<Vec<u8>> {
  let mut resp = Err(anyhow::Error::msg("addresses empty??"));
  for addr in addresses.iter().copied() {
    resp = match transport {
      Transport::Udp => udp_query(addr, query_bytes, qname).await,
      Transport::Tcp => tcp_query(addr, query_bytes, qname).await,
    };
    if resp.is_ok() {
      break;
    }
  }
  resp
}

async fn udp_query(addr: SocketAddr, query: &[u8], qname: &Name) -> anyhow::Result<Vec<u8>> {
  let local = if addr.is_ipv4() {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
  } else {
    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
  };

  let socket = UdpSocket::bind(local).await?;

  let send_recv = async {
    socket.send_to(query, addr).await?;
    let mut buf = [0u8; UDP_MAX_PACKET_SIZE];
    let (n, _) = socket.recv_from(&mut buf).await?;
    Ok::<_, io::Error>(buf[..n].to_vec())
  };

  send_recv
    .or(async {
      Timer::after(UDP_TIMEOUT).await;
      Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
    })
    .await
    .with_context(|| format!("upstream error: {addr:?}, {qname}"))
}

async fn tcp_query(addr: SocketAddr, query: &[u8], qname: &Name) -> anyhow::Result<Vec<u8>> {
  let connect = async {
    let mut stream = TcpStream::connect(addr).await?;

    let len = u16::try_from(query.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(query).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    anyhow::Ok(resp)
  };

  connect
    .or(async {
      Timer::after(TCP_TIMEOUT).await;
      Err(io::Error::new(io::ErrorKind::TimedOut, "timeout").into())
    })
    .await
    .with_context(|| format!("upstream error: {addr:?}, {qname}"))
}
