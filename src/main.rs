mod config;

use std::mem;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use config::Config;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{RData, Record, RecordType};
use smol::future::FutureExt as _;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpStream, UdpSocket};

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PKT: usize = 4096;

#[derive(Clone)]
struct Upstream {
  domains: Vec<String>,
  addresses: Vec<String>,
  strip_a: bool,
  dns64_prefix: Option<Ipv6Addr>,
}

struct App {
  upstreams: Vec<Upstream>,
  default_addrs: Vec<String>,
}

impl App {
  fn new(config: &Config) -> Self {
    let upstreams = config
      .upstreams
      .iter()
      .map(|u| Upstream {
        domains: u.domains.clone(),
        addresses: u.addresses.clone(),
        strip_a: u.strip_a,
        dns64_prefix: u.dns64_prefix,
      })
      .collect();
    App { default_addrs: config.default_upstream.clone(), upstreams }
  }

  fn domain_matches(qname: &str, domain: &str) -> bool {
    let qlen = qname.len();
    let dlen = domain.len();
    if dlen > qlen {
      return false;
    }
    qname[qlen - dlen..]
      .chars()
      .zip(domain.chars())
      .all(|(a, b)| a.eq_ignore_ascii_case(&b))
  }

  fn select_upstream(&self, qname: &str) -> Option<&Upstream> {
    self
      .upstreams
      .iter()
      .find(|u| u.domains.iter().any(|d| Self::domain_matches(qname, d)))
  }

  async fn tcp_query(&self, addr: &str, query: &[u8], qname: &str) -> Option<Vec<u8>> {
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
        return Err(std::io::Error::other("response too large"));
      }

      let mut resp = vec![0u8; resp_len];
      stream.read_exact(&mut resp).await?;
      Ok::<_, std::io::Error>(resp)
    };

    let result = connect
      .or(async {
        smol::Timer::after(TCP_TIMEOUT).await;
        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
      })
      .await;

    match result {
      Ok(resp) => Some(resp),
      Err(e) => {
        if e.kind() == std::io::ErrorKind::TimedOut {
          eprintln!("upstream timeout: {addr}, {qname}");
        } else {
          eprintln!("upstream error: {addr}, {qname}: {e}");
        }
        None
      }
    }
  }

  async fn resolve(&self, addresses: &[String], query_bytes: &[u8], qname: &str) -> Option<Vec<u8>> {
    for addr in addresses {
      let a = if addr.contains(':') {
        format!("[{}]:53", addr)
      } else {
        format!("{}:53", addr)
      };
      if let Some(resp) = self.tcp_query(&a, query_bytes, qname).await {
        return Some(resp);
      }
    }
    None
  }

  fn synthesize_aaaa(&self, prefix: &Ipv6Addr, a_record: &Record) -> Option<Record> {
    let a_rdata = match &a_record.data {
      RData::A(a) => a.0,
      _ => return None,
    };

    let prefix_bytes = prefix.octets();
    let a_bytes = a_rdata.octets();

    let mut ipv6_bytes = [0u8; 16];
    ipv6_bytes[..12].copy_from_slice(&prefix_bytes[..12]);
    ipv6_bytes[12..].copy_from_slice(&a_bytes);

    let ipv6 = Ipv6Addr::from(ipv6_bytes);

    let mut rr = Record::from_rdata(a_record.name.clone(), a_record.ttl, RData::AAAA(AAAA(ipv6)));
    rr.dns_class = a_record.dns_class;
    Some(rr)
  }

  async fn handle_dns64(&self, query: &Message, upstream: &Upstream) -> Option<Vec<u8>> {
    let prefix = upstream.dns64_prefix?;
    let qname = query.queries.first().map(|q| q.name().to_string()).unwrap_or_default();

    let mut a_query = Message::new(query.id, MessageType::Query, OpCode::Query);
    a_query.metadata.recursion_desired = true;

    for q in &query.queries {
      a_query.add_query(hickory_proto::op::Query::query(q.name.clone(), RecordType::A));
    }

    let a_bytes = a_query.to_vec().ok()?;
    let a_resp_bytes = self.resolve(&upstream.addresses, &a_bytes, &qname).await?;
    let a_resp = Message::from_vec(&a_resp_bytes).ok()?;

    let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;

    for q in &query.queries {
      resp.add_query(q.clone());
    }

    let mut n = 0;
    for rr in &a_resp.answers {
      if rr.record_type() == RecordType::A
        && let Some(aaaa) = self.synthesize_aaaa(&prefix, rr)
      {
        resp.add_answer(aaaa);
        n += 1;
      }
    }

    eprintln!("dns64: {qname} synthesized={n}");
    resp.to_vec().ok()
  }

  async fn handle_query(&self, query: &Message, upstream: Option<&Upstream>) -> Option<Vec<u8>> {
    let qtype = query.queries.first().map(|q| q.query_type()).unwrap_or(RecordType::A);
    let qname = query.queries.first().map(|q| q.name().to_string()).unwrap_or_default();

    if let Some(up) = upstream
      && up.dns64_prefix.is_some()
      && qtype == RecordType::AAAA
    {
      return self.handle_dns64(query, up).await;
    }

    let query_bytes = query.to_vec().ok()?;

    let addresses = match upstream {
      Some(up) => &up.addresses[..],
      None => &self.default_addrs[..],
    };

    let resp_bytes = self.resolve(addresses, &query_bytes, &qname).await?;

    let mut resp = Message::from_vec(&resp_bytes).ok()?;
    resp.metadata.id = query.id;

    if let Some(up) = upstream
      && up.strip_a
    {
      let total = resp.answers.len();
      let answers = mem::take(&mut resp.answers);
      for rr in answers {
        if rr.record_type() != RecordType::A {
          resp.add_answer(rr);
        }
      }
      let stripped = total - resp.answers.len();
      eprintln!("strip_a: {qname} stripped={stripped}");
    }

    resp.to_vec().ok()
  }
}

fn usage(prog: &str) {
  eprintln!("Usage: {} [-c config.toml]", prog);
  eprintln!("  -c PATH   path to config file (default: weirdns.toml)");
  eprintln!("  -h        show this help");
}

fn parse_args() -> String {
  let mut config_path = String::from("weirdns.toml");
  let args: Vec<String> = std::env::args().collect();
  let mut i = 1;
  while i < args.len() {
    match args[i].as_str() {
      "-c" => {
        i += 1;
        if i < args.len() {
          config_path = args[i].clone();
        }
      }
      "-h" => {
        usage(&args[0]);
        std::process::exit(0);
      }
      _ => {
        usage(&args[0]);
        std::process::exit(1);
      }
    }
    i += 1;
  }
  config_path
}

fn main() {
  let ex = smol::LocalExecutor::new();

  smol::block_on(ex.run(async {
    let config_path = parse_args();
    let config = Config::load(&config_path);
    let listen_addr = format!("{}:{}", config.listen_host, config.listen_port);

    let app = Arc::new(App::new(&config));

    let socket = Arc::new(UdpSocket::bind(&listen_addr).await.unwrap_or_else(|e| {
      eprintln!("bind {}: {}", listen_addr, e);
      std::process::exit(1);
    }));

    eprintln!("listening on {listen_addr}");

    let mut buf = vec![0u8; MAX_PKT];
    loop {
      let (n, src) = match socket.recv_from(&mut buf).await {
        Ok(v) => v,
        Err(e) => {
          eprintln!("recvfrom: {e}");
          continue;
        }
      };

      let query = match Message::from_vec(&buf[..n]) {
        Ok(q) => q,
        Err(_) => {
          eprintln!("failed to parse query from {src}");
          continue;
        }
      };

      let qname = query.queries.first().map(|q| q.name().to_string()).unwrap_or_default();
      let qtype = query.queries.first().map(|q| q.query_type()).unwrap_or(RecordType::A);

      let app = app.clone();
      let socket = socket.clone();

      ex.spawn(async move {
        let upstream = app.select_upstream(&qname);
        let up_label = upstream.map(|u| u.domains.join(",")).unwrap_or_else(|| "default".into());

        eprintln!("query: {src} {qname} {qtype:?} upstream={up_label}");

        if let Some(resp) = app.handle_query(&query, upstream).await {
          eprintln!("response: {src} {qname} len={}", resp.len());
          let _ = socket.send_to(&resp, src).await;
        } else {
          eprintln!("no upstream response: {src}, {qname}");
        }
      })
      .detach();
    }
  }));
}
