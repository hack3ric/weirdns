mod config;
mod dns;
mod dns64;

use either::Either;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use smol::LocalExecutor;
use smol::future::pending;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpListener, UdpSocket};
use std::mem;
use std::net::SocketAddr;
use std::process::exit;
use std::rc::Rc;

use crate::config::{Config, Rule};
use crate::dns::Transport;

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

  async fn handle_query(&self, query: &Message, src: SocketAddr, transport: Transport) -> Option<Vec<u8>> {
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
      && rule.dns64.is_some()
      && qtype == RecordType::AAAA
    {
      dns64::handle_dns64(query, rule, transport).await
    } else {
      let query_bytes = query.to_vec().ok()?;

      let addresses = match rule {
        Some(rule) => &rule.upstream[..],
        None => &self.config.upstream[..],
      };

      let resp_bytes = dns::resolve(addresses, &query_bytes, qname, transport).await?;

      if let Some(rule) = rule
        && rule.strip_a
      {
        let mut resp = Message::from_vec(&resp_bytes).ok()?;
        resp.metadata.id = query.id;
        let total = resp.answers.len();
        let answers = mem::take(&mut resp.answers);
        for rr in answers {
          if rr.record_type() != RecordType::A {
            resp.add_answer(rr);
          }
        }
        let stripped = total - resp.answers.len();
        eprintln!("strip_a: {qname} stripped={stripped}");
        Some(Either::Left(resp))
      } else {
        Some(Either::Right(resp_bytes))
      }
    };

    if let Some(Ok(resp)) = resp.map(|x| x.either(|x| x.to_vec(), Ok)) {
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

/// DNS mangler for custom DNS64 behaviours
#[derive(argh::FromArgs)]
struct Cli {
  /// path to config file
  #[argh(option, short = 'c')]
  config: String,
}

async fn run(ex: Rc<LocalExecutor<'static>>, config: Config) {
  let app = Rc::new(App::new(config));

  for addr in app.config.listen.iter().copied() {
    let socket = Rc::new(UdpSocket::bind(addr).await.unwrap_or_else(|e| {
      eprintln!("error binding UDP {addr}: {e}");
      exit(1);
    }));

    ex.spawn({
      let app = app.clone();
      let ex = ex.clone();
      async move {
        let mut buf = [0u8; dns::UDP_MAX_PACKET_SIZE];
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
            Err(e) => {
              eprintln!("failed to parse query from {src}: {e}");
              continue;
            }
          };

          ex.spawn({
            let app = app.clone();
            let socket = socket.clone();
            async move {
              if let Some(resp) = app.handle_query(&query, src, Transport::Udp).await {
                let _ = socket.send_to(&resp, src).await;
              }
            }
          })
          .detach();
        }
      }
    })
    .detach();
  }

  for addr in app.config.listen.iter().copied() {
    let listener = Rc::new(TcpListener::bind(addr).await.unwrap_or_else(|e| {
      eprintln!("error binding TCP {addr}: {e}");
      exit(1);
    }));

    ex.spawn({
      let app = app.clone();
      let ex = ex.clone();
      async move {
        loop {
          let (mut stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
              eprintln!("tcp accept: {e}");
              continue;
            }
          };

          ex.spawn({
            let app = app.clone();
            async move {
              let mut len_buf = [0u8; 2];
              if stream.read_exact(&mut len_buf).await.is_err() {
                return;
              }
              let query_len = u16::from_be_bytes(len_buf) as usize;
              let mut query_buf = vec![0u8; query_len];
              if stream.read_exact(&mut query_buf).await.is_err() {
                return;
              }

              let query = match Message::from_vec(&query_buf) {
                Ok(q) => q,
                Err(e) => {
                  eprintln!("failed to parse TCP query from {src}: {e}");
                  return;
                }
              };

              if let Some(resp) = app.handle_query(&query, src, Transport::Tcp).await {
                let resp_len = resp.len() as u16;
                let _ = stream.write_all(&resp_len.to_be_bytes()).await;
                let _ = stream.write_all(&resp).await;
              }
            }
          })
          .detach();
        }
      }
    })
    .detach();
  }

  {
    let addrs_str = format!("{:?}", app.config.listen);
    let addrs_str = &addrs_str[1..addrs_str.len() - 1];
    eprintln!("listening on {addrs_str}");
  }

  pending::<()>().await;
}

fn main() {
  let cli: Cli = argh::from_env();
  let config_path = cli.config;
  let content = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
    eprintln!("cannot open {config_path}: {e}");
    exit(1);
  });
  let config: Config = toml::from_str(&content).unwrap_or_else(|e| {
    eprintln!("parse error in {config_path}: {e}");
    exit(1);
  });

  let ex = Rc::new(smol::LocalExecutor::new());
  smol::block_on(ex.run(run(ex.clone(), config)))
}
