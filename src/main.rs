use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::Deserialize;
use serde_with::{DeserializeAs, serde_as};
use smol::future::FutureExt as _;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpStream, UdpSocket};
use std::mem;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PKT: usize = 4096;
const DNS_PORT: u16 = 53;

struct Addr<const PORT: u16>;

impl<'de, const PORT: u16> DeserializeAs<'de, SocketAddr> for Addr<PORT> {
  fn deserialize_as<D>(d: D) -> Result<SocketAddr, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = String::deserialize(d)?;
    if let Ok(addr) = s.parse::<SocketAddr>() {
      return Ok(addr);
    }
    match s.parse::<IpAddr>() {
      Ok(ip) => Ok(SocketAddr::new(ip, PORT)),
      Err(_) => Err(serde::de::Error::custom(format!(
        "expected IP or socket address, got: {s}"
      ))),
    }
  }
}

#[serde_as]
#[derive(Deserialize)]
struct Config {
  listen: SocketAddr,
  #[serde_as(as = "Vec<Addr<DNS_PORT>>")]
  upstream: Vec<SocketAddr>,
  #[serde(rename = "rule")]
  rules: Vec<Rule>,
}

#[serde_as]
#[derive(Deserialize)]
struct Rule {
  domains: Vec<Name>,
  #[serde(default)]
  #[serde_as(as = "Vec<Addr<DNS_PORT>>")]
  upstream: Vec<SocketAddr>,
  dns64_prefix: Option<Ipv6Addr>,
  #[serde(default)]
  strip_a: bool,
}

struct App {
  config: Config,
}

impl App {
  fn new(config: Config) -> Self {
    App { config }
  }

  fn select_rule(&self, qname: &Name) -> Option<&Rule> {
    self
      .config
      .rules
      .iter()
      .find(|u| u.domains.iter().any(|d| domain_matches(qname, d)))
  }

  async fn handle_query(&self, query: &Message, rule: Option<&Rule>) -> Option<Vec<u8>> {
    let root = Name::root();
    let (qtype, qname) = query
      .queries
      .first()
      .map(|q| (q.query_type(), q.name()))
      .unwrap_or((RecordType::A, &root));

    if let Some(rule) = rule
      && rule.dns64_prefix.is_some()
      && qtype == RecordType::AAAA
    {
      return handle_dns64(query, rule).await;
    }

    let query_bytes = query.to_vec().ok()?;

    let addresses = match rule {
      Some(rule) => &rule.upstream[..],
      None => &self.config.upstream[..],
    };

    let resp_bytes = resolve(addresses, &query_bytes, qname).await?;

    let mut resp = Message::from_vec(&resp_bytes).ok()?;
    resp.metadata.id = query.id;

    if let Some(rule) = rule
      && rule.strip_a
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

fn domain_matches(qname: &Name, domain: &Name) -> bool {
  qname.num_labels() >= domain.num_labels()
    && qname
      .iter()
      .rev()
      .zip(domain.iter().rev())
      .all(|(a, b)| a.eq_ignore_ascii_case(b))
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
        eprintln!("upstream timeout: {addr:?}, {qname}");
      } else {
        eprintln!("upstream error: {addr:?}, {qname}: {e}");
      }
      None
    }
  }
}

async fn resolve(addresses: &[SocketAddr], query_bytes: &[u8], qname: &Name) -> Option<Vec<u8>> {
  for addr in addresses {
    if let Some(resp) = tcp_query(addr, query_bytes, qname).await {
      return Some(resp);
    }
  }
  None
}

fn synthesize_aaaa(prefix: Ipv6Addr, a_record: &Record) -> Option<Record> {
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

async fn handle_dns64(query: &Message, rule: &Rule) -> Option<Vec<u8>> {
  let prefix = rule.dns64_prefix?;
  let root = Name::root();
  let qname = query.queries.first().map(|q| q.name()).unwrap_or(&root);

  let mut a_query = Message::new(query.id, MessageType::Query, OpCode::Query);
  a_query.metadata.recursion_desired = true;

  for q in &query.queries {
    a_query.add_query(hickory_proto::op::Query::query(q.name.clone(), RecordType::A));
  }

  let a_bytes = a_query.to_vec().ok()?;
  let a_resp_bytes = resolve(&rule.upstream, &a_bytes, qname).await?;
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
      && let Some(aaaa) = synthesize_aaaa(prefix, rr)
    {
      resp.add_answer(aaaa);
      n += 1;
    }
  }

  eprintln!("dns64: {qname} synthesized={n}");
  resp.to_vec().ok()
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

  let config_path = parse_args();
  let content = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
    eprintln!("Cannot open {config_path}: {e}");
    std::process::exit(1);
  });

  let cfg: Config = toml::from_str(&content).unwrap_or_else(|e| {
    eprintln!("Parse error in {config_path}: {e}");
    std::process::exit(1);
  });

  smol::block_on(ex.run(async {
    let app = Rc::new(App::new(cfg));

    let socket = Rc::new(UdpSocket::bind(app.config.listen).await.unwrap_or_else(|e| {
      eprintln!("bind {:?}: {e}", app.config.listen);
      std::process::exit(1);
    }));

    eprintln!("listening on {:?}", app.config.listen);

    let mut buf = [0u8; MAX_PKT];
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

      let qname = query.queries.first().map(|q| q.name().clone()).unwrap_or_else(Name::root);
      let qtype = query.queries.first().map(|q| q.query_type()).unwrap_or(RecordType::A);

      let app = app.clone();
      let socket = socket.clone();

      ex.spawn(async move {
        let rule = app.select_rule(&qname);
        let label = rule
          .map(|u| u.domains.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","))
          .unwrap_or_else(|| "default".into());

        eprintln!("query: {src} {qname} {qtype:?} rule={label}");

        if let Some(resp) = app.handle_query(&query, rule).await {
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
