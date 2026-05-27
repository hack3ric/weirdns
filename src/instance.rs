use anyhow::Context;
use async_executor::LocalExecutor;
use async_net::{TcpListener, TcpStream, UdpSocket};
use fqdn::FQDN;
use fqdn_trie::FqdnTrieMap;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use simple_dns::{Name, Packet, QTYPE, TYPE};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::rc::Rc;

use crate::config::{Config, Rule};
use crate::glob::{GlobValue, RuleValue, contains_glob, parse_domain_pattern};
use crate::transport::{self, Transport};
use crate::{dns64, print_anyhow_error};

pub struct Instance {
  config: Config,
  trie: FqdnTrieMap<FQDN, RuleValue>,
}

impl Instance {
  pub fn new(config: Config) -> Self {
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
              let value = RuleValue { exact: Some(idx), ..Default::default() };
              trie.insert(fqdn, value);
            }
          }
        }
      }
    }
    Instance { config, trie }
  }

  fn select_rule(&self, qname: &Name) -> Option<&Rule> {
    let fqdn = FQDN::from_ascii_str(&qname.to_string()).ok()?;
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

  async fn handle_query(&self, query: Packet<'_>, src: SocketAddr, transport: Transport) -> anyhow::Result<Vec<u8>> {
    let (qtype, qname) = query
      .questions
      .first()
      .map(|q| (question_type(q.qtype), q.qname.clone()))
      .unwrap_or_else(|| (TYPE::A, Name::new_unchecked("")));

    let rule = self.select_rule(&qname);

    if self.config.log {
      let label: Cow<'static, str> = rule.map(|u| u.domains.join(",").into()).unwrap_or_else(|| "default".into());
      eprintln!("query: {src} {qname} {qtype:?} rule={label}");
    }

    let addresses = rule
      .and_then(|r| r.upstream.as_deref())
      .unwrap_or(&self.config.default_upstream[..]);

    let resp = self.resolve_query(query, &qname, qtype, rule, addresses, transport).await;
    if let Ok(resp) = &resp
      && self.config.log
    {
      eprintln!("response: {src} {qname} len={}", resp.len());
    }
    resp
  }

  async fn resolve_query(
    &self,
    query: Packet<'_>,
    qname: &Name<'_>,
    qtype: TYPE,
    rule: Option<&Rule>,
    addresses: &[SocketAddr],
    transport: Transport,
  ) -> anyhow::Result<Vec<u8>> {
    match (rule, qtype) {
      (Some(rule), TYPE::AAAA) if rule.dns64_prefix.is_some() => {
        dns64::handle_dns64(query, rule, addresses, transport, self.config.log).await
      }
      (Some(rule), TYPE::PTR) if rule.dns64_prefix.is_some() => {
        dns64::handle_dns64_rdns(query, rule, addresses, transport, self.config.log).await
      }
      _ => {
        let query_bytes = query.build_bytes_vec_compressed()?;
        let resp_bytes = transport::resolve(addresses, &query_bytes, qname, transport).await?;
        match rule {
          Some(rule) if rule.strip_a => self.apply_strip_a(qname, query.id(), qtype, resp_bytes),
          _ => Ok(resp_bytes),
        }
      }
    }
  }

  fn apply_strip_a(
    &self,
    qname: &Name,
    query_id: u16,
    qtype: TYPE,
    resp_bytes: Vec<u8>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut resp = Packet::parse(&resp_bytes)?;
    resp.set_id(query_id);
    let total = resp.answers.len();
    if qtype == TYPE::A {
      resp.answers.clear();
    } else {
      resp.answers.retain(|rr| rr.rdata.type_code() != TYPE::A);
    }
    let stripped = total - resp.answers.len();
    if self.config.log {
      eprintln!("strip_a: {qname} stripped={stripped}");
    }
    Ok(resp.build_bytes_vec_compressed()?)
  }
}

pub async fn start_instance(ex: Rc<LocalExecutor<'static>>, config: Config) -> anyhow::Result<()> {
  let instance = Rc::new(Instance::new(config));

  for addr in instance.config.listen.iter().copied() {
    spawn_udp_listener(ex.clone(), instance.clone(), addr).await?;
    spawn_tcp_listener(ex.clone(), instance.clone(), addr).await?;
  }

  let addrs_str = (instance.config.listen.iter())
    .map(ToString::to_string)
    .collect::<Vec<_>>()
    .join(", ");
  eprintln!("listening on {addrs_str}");
  Ok(())
}

async fn spawn_udp_listener(
  ex: Rc<LocalExecutor<'static>>,
  instance: Rc<Instance>,
  addr: SocketAddr,
) -> anyhow::Result<()> {
  let socket = Rc::new(
    UdpSocket::bind(addr)
      .await
      .with_context(|| format!("error binding UDP {addr}"))?,
  );

  ex.spawn({
    let instance = instance.clone();
    let ex = ex.clone();
    async move {
      let mut buf = [0u8; transport::UDP_MAX_PACKET_SIZE];
      loop {
        let _ = print_anyhow_result_async(async {
          let (n, src) = socket.recv_from(&mut buf).await.context("recvfrom")?;
          let query_bytes = buf[..n].to_vec();
          ex.spawn(print_anyhow_result_async({
            let instance = instance.clone();
            let socket = socket.clone();
            async move {
              let query = parse_query_bytes(&query_bytes, src, "query")?;
              let resp = instance.handle_query(query, src, Transport::Udp).await?;
              socket.send_to(&resp, src).await?;
              anyhow::Ok(())
            }
          }))
          .detach();
          anyhow::Ok(())
        })
        .await;
      }
    }
  })
  .detach();

  Ok(())
}

async fn spawn_tcp_listener(
  ex: Rc<LocalExecutor<'static>>,
  instance: Rc<Instance>,
  addr: SocketAddr,
) -> anyhow::Result<()> {
  let listener = Rc::new(
    TcpListener::bind(addr)
      .await
      .with_context(|| format!("error binding TCP {addr}"))?,
  );

  ex.spawn({
    let instance = instance.clone();
    let ex = ex.clone();
    async move {
      loop {
        let Ok((stream, src)) = listener.accept().await.context("tcp accept").inspect_err(print_anyhow_error) else {
          continue;
        };

        ex.spawn(print_anyhow_result_async(handle_tcp_stream(
          instance.clone(),
          stream,
          src,
        )))
        .detach();
      }
    }
  })
  .detach();

  Ok(())
}

async fn handle_tcp_stream(instance: Rc<Instance>, mut stream: TcpStream, src: SocketAddr) -> anyhow::Result<()> {
  let query_buf = read_tcp_query_bytes(&mut stream).await?;
  let query = parse_query_bytes(&query_buf, src, "TCP query")?;

  let resp = instance.handle_query(query, src, Transport::Tcp).await?;
  let resp_len = u16::try_from(resp.len())?;
  stream.write_all(&resp_len.to_be_bytes()).await?;
  stream.write_all(&resp).await?;
  Ok(())
}

async fn read_tcp_query_bytes(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
  let mut len_buf = [0u8; 2];
  stream.read_exact(&mut len_buf).await?;
  let query_len = u16::from_be_bytes(len_buf) as usize;
  let mut query_buf = vec![0u8; query_len];
  stream.read_exact(&mut query_buf).await?;
  Ok(query_buf)
}

fn parse_query_bytes<'a>(buf: &'a [u8], src: SocketAddr, label: &str) -> anyhow::Result<Packet<'a>> {
  Packet::parse(buf).with_context(|| format!("failed to parse {label} from {src}"))
}

async fn print_anyhow_result_async<T>(f: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
  f.await.inspect_err(print_anyhow_error)
}

fn question_type(qtype: QTYPE) -> TYPE {
  match qtype {
    QTYPE::TYPE(ty) => ty,
    _ => TYPE::Unknown(u16::from(qtype)),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_config(rules: Vec<crate::config::Rule>) -> Config {
    Config {
      listen: Box::new([]),
      default_upstream: Box::new([]),
      rules: rules.into_boxed_slice(),
      log: false,
    }
  }

  fn make_rule(domains: &[&str]) -> crate::config::Rule {
    crate::config::Rule {
      domains: domains
        .iter()
        .map(|d| Box::<str>::from(*d))
        .collect::<Vec<_>>()
        .into_boxed_slice(),
      upstream: None,
      dns64_prefix: None,
      dns64_force_synth: false,
      strip_a: false,
    }
  }

  fn name(s: &str) -> Name<'_> {
    Name::new(s.trim_end_matches('.')).unwrap()
  }

  #[test]
  fn integration_exact_match() {
    let rules = vec![make_rule(&["example.com"]), make_rule(&["other.com"])];
    let instance = Instance::new(make_config(rules));
    assert!(instance.select_rule(&name("example.com")).is_some());
    assert!(instance.select_rule(&name("sub.example.com")).is_some());
    assert!(instance.select_rule(&name("other.com")).is_some());
    assert!(instance.select_rule(&name("unmatched.com")).is_none());
  }

  #[test]
  fn integration_glob_single_wildcard_label() {
    let rules = vec![make_rule(&["*.example.com"])];
    let instance = Instance::new(make_config(rules));
    assert!(instance.select_rule(&name("foo.example.com")).is_some());
    assert!(instance.select_rule(&name("bar.example.com")).is_some());
    assert!(instance.select_rule(&name("sub.foo.example.com")).is_some());
    assert!(instance.select_rule(&name("foo.other.com")).is_none());
  }

  #[test]
  fn integration_glob_within_label() {
    let rules = vec![make_rule(&["chatgpt-async-webps-prod-*-*.webpubsub.azure.com"])];
    let instance = Instance::new(make_config(rules));
    assert!(
      instance
        .select_rule(&name("chatgpt-async-webps-prod-someid-123.webpubsub.azure.com"))
        .is_some()
    );
    assert!(
      instance
        .select_rule(&name("chatgpt-async-webps-prod-abc-42.webpubsub.azure.com"))
        .is_some()
    );
    assert!(
      instance
        .select_rule(&name("other-prod-someid-123.webpubsub.azure.com"))
        .is_none()
    );
    assert!(
      instance
        .select_rule(&name("x.chatgpt-async-webps-prod-someid-123.webpubsub.azure.com"))
        .is_some()
    );
  }

  #[test]
  fn integration_exact_priority_over_glob() {
    let rules = vec![make_rule(&["*.example.com"]), make_rule(&["exact.example.com"])];
    let instance = Instance::new(make_config(rules));
    let r = instance.select_rule(&name("exact.example.com")).unwrap();
    assert_eq!(r.domains.join(","), "exact.example.com");
  }

  #[test]
  fn integration_question_mark() {
    let rules = vec![make_rule(&["app-?.example.com"])];
    let instance = Instance::new(make_config(rules));
    assert!(instance.select_rule(&name("app-1.example.com")).is_some());
    assert!(instance.select_rule(&name("app-x.example.com")).is_some());
    assert!(instance.select_rule(&name("app-12.example.com")).is_none());
  }

  #[test]
  fn integration_glob_at_root_match_any() {
    let rules = vec![make_rule(&["*"])];
    let instance = Instance::new(make_config(rules));
    assert!(instance.select_rule(&name("example.com")).is_some());
    assert!(instance.select_rule(&name("foo.bar.example.com")).is_some());
    assert!(instance.select_rule(&name("com")).is_some());
  }
}
