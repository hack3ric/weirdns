mod dns;
mod dns64;

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use serde::Deserialize;
use serde_with::{DeserializeAs, OneOrMany, serde_as};
use smol::net::UdpSocket;
use std::mem;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::exit;
use std::rc::Rc;

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
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  listen: Vec<SocketAddr>,
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  upstream: Vec<SocketAddr>,
  #[serde(rename = "rule")]
  rules: Vec<Rule>,
}

#[serde_as]
#[derive(Deserialize)]
struct Rule {
  #[serde_as(as = "OneOrMany<_>")]
  domains: Vec<Name>,
  #[serde(default)]
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
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

  async fn handle_query(&self, query: &Message, src: SocketAddr) -> Option<Vec<u8>> {
    let root = Name::root();
    let (qname, qtype) = query
      .queries
      .first()
      .map(|q| (q.name(), q.query_type()))
      .unwrap_or((&root, RecordType::A));

    let rule = self.select_rule(qname);
    let label = rule
      .map(|u| u.domains.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","))
      .unwrap_or_else(|| "default".into());

    eprintln!("query: {src} {qname} {qtype:?} rule={label}");

    let root = Name::root();
    let (qtype, qname) = query
      .queries
      .first()
      .map(|q| (q.query_type(), q.name()))
      .unwrap_or((RecordType::A, &root));

    let resp = if let Some(rule) = rule
      && rule.dns64_prefix.is_some()
      && qtype == RecordType::AAAA
    {
      dns64::handle_dns64(query, rule).await
    } else {
      let query_bytes = query.to_vec().ok()?;

      let addresses = match rule {
        Some(rule) => &rule.upstream[..],
        None => &self.config.upstream[..],
      };

      let resp_bytes = dns::resolve(addresses, &query_bytes, qname).await?;

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
      Some(resp)
    };

    if let Some(Ok(resp)) = resp.map(|x| x.to_vec()) {
      eprintln!("response: {src} {qname} len={}", resp.len());
      Some(resp)
    } else {
      eprintln!("no upstream response: {src}, {qname}");
      None
    }
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

/// DNS64 gateway proxy
#[derive(argh::FromArgs)]
struct Cli {
  /// path to config file
  #[argh(option, short = 'c')]
  config: String,
}

fn main() {
  let ex = smol::LocalExecutor::new();

  let cli: Cli = argh::from_env();
  let config_path = cli.config;
  let content = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
    eprintln!("cannot open {config_path}: {e}");
    exit(1);
  });
  let cfg: Config = toml::from_str(&content).unwrap_or_else(|e| {
    eprintln!("parse error in {config_path}: {e}");
    exit(1);
  });

  smol::block_on(ex.run(async {
    let app = Rc::new(App::new(cfg));

    let comma_separated = format!("{:?}", app.config.listen);
    let comma_separated = &comma_separated[1..comma_separated.len() - 1];
    let socket = Rc::new(UdpSocket::bind(&app.config.listen[..]).await.unwrap_or_else(|e| {
      eprintln!("error binding {comma_separated}: {e}");
      exit(1);
    }));

    eprintln!("listening on {comma_separated}");

    let mut buf = [0u8; dns::MAX_PKT];
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

      let app = app.clone();
      let socket = socket.clone();

      ex.spawn(async move {
        if let Some(resp) = app.handle_query(&query, src).await {
          let _ = socket.send_to(&resp, src).await;
        }
      })
      .detach();
    }
  }))
}
