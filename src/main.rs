mod config;
mod dns;
mod dns64;
mod glob;

use either::Either;
use fqdn::FQDN;
use fqdn_trie::FqdnTrieMap;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use smol::LocalExecutor;
use smol::future::pending;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::{TcpListener, TcpStream, UdpSocket};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::process::exit;
use std::rc::Rc;

use crate::config::{Config, Rule};
use crate::dns::Transport;
use crate::glob::{GlobValue, RuleValue, contains_glob, parse_domain_pattern};

struct App {
  config: Config,
  trie: FqdnTrieMap<FQDN, RuleValue>,
  log_enabled: bool,
}

impl App {
  fn new(config: Config, log_enabled: bool) -> Self {
    let mut trie = FqdnTrieMap::with_key_root(FQDN::default(), RuleValue::default());
    for (idx, rule) in config.rules.iter().enumerate() {
      for domain in rule.domains.iter() {
        if contains_glob(domain) {
          if let Some((suffix, prefix)) = parse_domain_pattern(domain) {
            let gv = GlobValue { prefix, rule: idx };
            match trie.get_mut(&suffix) {
              Some(value) => value.globs.push(gv),
              None => {
                let mut value = RuleValue::default();
                value.globs.push(gv);
                trie.insert(suffix, value);
              }
            }
          }
        } else {
          let fqdn = FQDN::from_ascii_str(domain).expect("invalid domain in config");
          match trie.get_mut(&fqdn) {
            Some(value) => value.exact = Some(idx),
            None => {
              let mut value = RuleValue::default();
              value.exact = Some(idx);
              trie.insert(fqdn, value);
            }
          }
        }
      }
    }
    App { config, trie, log_enabled }
  }

  fn select_rule(&self, qname: &Name) -> Option<&Rule> {
    let fqdn = qname.to_bytes().ok().and_then(|b| FQDN::try_from(b).ok())?;
    let (suffix, value) = self.trie.lookup_key_value(&fqdn);
    if let Some(idx) = value.exact {
      return Some(&self.config.rules[idx]);
    }
    for gv in &value.globs {
      if gv.matches(&fqdn, suffix.as_ref()) {
        return Some(&self.config.rules[gv.rule]);
      }
    }
    None
  }

  async fn handle_query(&self, query: Message, src: SocketAddr, transport: Transport) -> Option<Vec<u8>> {
    let (qtype, qname) = query
      .queries
      .first()
      .map(|q| (q.query_type(), q.name().clone()))
      .unwrap_or_else(|| (RecordType::A, Name::root()));

    let rule = self.select_rule(&qname);

    if self.log_enabled {
      let label: Cow<'static, str> = rule.map(|u| u.domains.join(",").into()).unwrap_or_else(|| "default".into());
      eprintln!("query: {src} {qname} {qtype:?} rule={label}");
    }

    let addresses = rule
      .and_then(|r| r.upstream.as_deref())
      .unwrap_or(&self.config.default_upstream[..]);

    let resp = self.resolve_query(query, &qname, qtype, rule, addresses, transport).await;

    if let Some(resp) = resp {
      if self.log_enabled {
        eprintln!("response: {src} {qname} len={}", resp.len());
      }
      Some(resp)
    } else {
      if self.log_enabled {
        eprintln!("no upstream response: {src}, {qname}");
      }
      None
    }
  }

  async fn resolve_query(
    &self,
    query: Message,
    qname: &Name,
    qtype: RecordType,
    rule: Option<&Rule>,
    addresses: &[SocketAddr],
    transport: Transport,
  ) -> Option<Vec<u8>> {
    match (rule, qtype) {
      (Some(rule), RecordType::AAAA) if rule.dns64_prefix.is_some() => {
        match dns64::handle_dns64(query, rule, addresses, transport, self.log_enabled).await? {
          Either::Left(msg) => msg.to_vec().ok(),
          Either::Right(bytes) => Some(bytes),
        }
      }
      (Some(rule), RecordType::PTR) if rule.dns64_prefix.is_some() => {
        match dns64::handle_dns64_rdns(query, rule, addresses, transport, self.log_enabled).await? {
          Either::Left(msg) => msg.to_vec().ok(),
          Either::Right(bytes) => Some(bytes),
        }
      }
      _ => {
        let query_bytes = query.to_vec().ok()?;
        let resp_bytes = dns::resolve(addresses, &query_bytes, qname, transport, self.log_enabled).await?;
        match rule {
          Some(rule) if rule.strip_a => self.apply_strip_a(qname, query.id, qtype, resp_bytes),
          _ => Some(resp_bytes),
        }
      }
    }
  }

  fn apply_strip_a(&self, qname: &Name, query_id: u16, qtype: RecordType, resp_bytes: Vec<u8>) -> Option<Vec<u8>> {
    let mut resp = Message::from_vec(&resp_bytes).ok()?;
    resp.metadata.id = query_id;
    let total = resp.answers.len();
    if qtype == RecordType::A {
      resp.answers.clear();
    } else {
      resp.answers.retain(|rr| rr.record_type() != RecordType::A);
    }
    let stripped = total - resp.answers.len();
    if self.log_enabled {
      eprintln!("strip_a: {qname} stripped={stripped}");
    }
    resp.to_vec().ok()
  }
}

/// DNS mangler for custom DNS64 behaviours
#[derive(argh::FromArgs)]
struct Cli {
  /// path to config file
  #[argh(option, short = 'c')]
  config: String,

  /// enable per-request verbose logging
  #[argh(switch, short = 'v')]
  verbose: bool,
}

async fn run(ex: Rc<LocalExecutor<'static>>, config: Config, log_enabled: bool) {
  let app = Rc::new(App::new(config, log_enabled));

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
              if let Some(resp) = app.handle_query(query, src, Transport::Udp).await {
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
              let query_buf = match read_tcp_query_bytes(&mut stream).await {
                Some(b) => b,
                None => return,
              };

              let query = match Message::from_vec(&query_buf) {
                Ok(q) => q,
                Err(e) => {
                  eprintln!("failed to parse TCP query from {src}: {e}");
                  return;
                }
              };

              if let Some(resp) = app.handle_query(query, src, Transport::Tcp).await {
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
    let addrs_str: Vec<String> = app.config.listen.iter().map(|a| a.to_string()).collect();
    eprintln!("listening on {}", addrs_str.join(", "));
  }

  pending::<()>().await;
}

async fn read_tcp_query_bytes(stream: &mut TcpStream) -> Option<Vec<u8>> {
  let mut len_buf = [0u8; 2];
  stream.read_exact(&mut len_buf).await.ok()?;
  let query_len = u16::from_be_bytes(len_buf) as usize;
  let mut query_buf = vec![0u8; query_len];
  stream.read_exact(&mut query_buf).await.ok()?;
  Some(query_buf)
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

  let log_enabled = config.enable_logging || cli.verbose;

  let ex = Rc::new(smol::LocalExecutor::new());
  smol::block_on(ex.run(run(ex.clone(), config, log_enabled)))
}

#[cfg(test)]
mod tests {
  use super::*;
  use hickory_proto::rr::Name;

  fn make_config(rules: Vec<crate::config::Rule>) -> Config {
    Config {
      listen: Box::new([]),
      default_upstream: Box::new([]),
      rules: rules.into_boxed_slice(),
      enable_logging: false,
    }
  }

  fn make_rule(domains: &[&str]) -> crate::config::Rule {
    crate::config::Rule {
      domains: domains.iter().map(|d| Box::<str>::from(*d)).collect::<Vec<_>>().into_boxed_slice(),
      upstream: None,
      dns64_prefix: None,
      dns64_force_synth: false,
      strip_a: false,
    }
  }

  fn name(s: &str) -> Name {
    let fqdn_str = if s.ends_with('.') { s.into() } else { format!("{s}.") };
    Name::from_ascii(&fqdn_str).unwrap()
  }

  #[test]
  fn integration_exact_match() {
    let rules = vec![make_rule(&["example.com"]), make_rule(&["other.com"])];
    let app = App::new(make_config(rules), false);
    assert!(app.select_rule(&name("example.com")).is_some());
    assert!(app.select_rule(&name("sub.example.com")).is_some());
    assert!(app.select_rule(&name("other.com")).is_some());
    assert!(app.select_rule(&name("unmatched.com")).is_none());
  }

  #[test]
  fn integration_glob_single_wildcard_label() {
    let rules = vec![make_rule(&["*.example.com"])];
    let app = App::new(make_config(rules), false);
    assert!(app.select_rule(&name("foo.example.com")).is_some());
    assert!(app.select_rule(&name("bar.example.com")).is_some());
    assert!(app.select_rule(&name("sub.foo.example.com")).is_some());
    assert!(app.select_rule(&name("foo.other.com")).is_none());
  }

  #[test]
  fn integration_glob_within_label() {
    let rules = vec![make_rule(
      &["chatgpt-async-webps-prod-*-*.webpubsub.azure.com"]
    )];
    let app = App::new(make_config(rules), false);
    assert!(app.select_rule(&name("chatgpt-async-webps-prod-someid-123.webpubsub.azure.com")).is_some());
    assert!(app.select_rule(&name("chatgpt-async-webps-prod-abc-42.webpubsub.azure.com")).is_some());
    assert!(!app.select_rule(&name("other-prod-someid-123.webpubsub.azure.com")).is_some());
    // subdomain: should match
    assert!(app.select_rule(&name("x.chatgpt-async-webps-prod-someid-123.webpubsub.azure.com")).is_some());
  }

  #[test]
  fn integration_exact_priority_over_glob() {
    let rules = vec![
      make_rule(&["*.example.com"]),
      make_rule(&["exact.example.com"]),
    ];
    let app = App::new(make_config(rules), false);
    let r = app.select_rule(&name("exact.example.com")).unwrap();
    assert_eq!(r.domains.join(","), "exact.example.com");
  }

  #[test]
  fn integration_question_mark() {
    let rules = vec![make_rule(&["app-?.example.com"])];
    let app = App::new(make_config(rules), false);
    assert!(app.select_rule(&name("app-1.example.com")).is_some());
    assert!(app.select_rule(&name("app-x.example.com")).is_some());
    assert!(!app.select_rule(&name("app-12.example.com")).is_some());
  }

  #[test]
  fn integration_glob_at_root_match_any() {
    let rules = vec![make_rule(&["*"])];
    let app = App::new(make_config(rules), false);
    assert!(app.select_rule(&name("example.com")).is_some());
    assert!(app.select_rule(&name("foo.bar.example.com")).is_some());
    assert!(app.select_rule(&name("com")).is_some());
  }
}

