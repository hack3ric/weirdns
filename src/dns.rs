use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::rr::Name;
use smol::future::FutureExt;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;

pub const TCP_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_PKT: usize = 4096;

pub async fn resolve(addresses: &[SocketAddr], query_bytes: &[u8], qname: &Name) -> Option<Vec<u8>> {
  for addr in addresses {
    if let Some(resp) = tcp_query(addr, query_bytes, qname).await {
      return Some(resp);
    }
  }
  None
}

async fn tcp_query(addr: &SocketAddr, query: &[u8], qname: &Name) -> Option<Vec<u8>> {
  let connect = async {
    let mut stream = TcpStream::connect(addr).await?;

    let len = query.len() as u16;
    let mut packet = Vec::with_capacity(2 + query.len());
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(query);
    stream.write_all(&packet).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len > MAX_PKT {
      return Err(io::Error::other("response too large"));
    }

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
      if e.kind() == io::ErrorKind::TimedOut {
        eprintln!("upstream timeout: {addr:?}, {qname}");
      } else {
        eprintln!("upstream error: {addr:?}, {qname}: {e}");
      }
      None
    }
  }
}
