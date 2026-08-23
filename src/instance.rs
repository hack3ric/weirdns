use crate::config::{Config, Rule};
use crate::glob::{GlobValue, RuleValue, contains_glob, parse_domain_pattern};
use crate::transport::{self, Transport};
use crate::{dns64, print_anyhow_error};
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

pub struct Instance {
  config: Config,
  trie: FqdnTrieMap<FQDN, RuleValue>,
}

impl Instance {
  pub fn new(mut config: Config) -> Self {
    add_dns64_rdns_rules(&mut config.rules);

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
        let resp_bytes = match (rule, qtype) {
          (Some(rule), TYPE::HTTPS | TYPE::SVCB) if rule.dns64_prefix.is_some() || rule.strip_a => {
            dns64::mangle_svcb_response(qname, resp_bytes, rule, self.config.log)?
          }
          _ => resp_bytes,
        };
        match rule {
          Some(rule) if rule.strip_a => self.apply_strip_a(qname, query.id(), qtype, resp_bytes),
          _ => Ok(resp_bytes),
        }
      }
    }
  }

  fn apply_strip_a(&self, qname: &Name, query_id: u16, qtype: TYPE, resp_bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
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

fn add_dns64_rdns_rules(rules: &mut Vec<Rule>) {
  let mut prefixes = Vec::new();
  for rule in rules.iter() {
    let Some(prefix) = rule.dns64_prefix else {
      continue;
    };
    if !prefixes.contains(&prefix) && !has_explicit_rdns_rule(rules, prefix) {
      prefixes.push(prefix);
    }
  }

  // prepend generated configs so it can be overriden by manual rules
  rules.splice(
    0..0,
    prefixes.into_iter().map(|prefix| Rule {
      domains: vec![dns64::rdns_domain(prefix).into_boxed_str()].into_boxed_slice(),
      upstream: None,
      dns64_prefix: Some(prefix),
      dns64_force_synth: false,
      strip_a: false,
    }),
  );
}

fn has_explicit_rdns_rule(rules: &[Rule], prefix: std::net::Ipv6Addr) -> bool {
  rules.iter().any(|rule| {
    rule.dns64_prefix == Some(prefix)
      && rule.domains.iter().any(|domain| {
        let domain = domain.trim_end_matches('.');
        domain.eq_ignore_ascii_case("ip6.arpa")
          || domain
            .get(domain.len().saturating_sub(".ip6.arpa".len())..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".ip6.arpa"))
      })
  })
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
  use futures_lite::future::block_on;
  use simple_dns::rdata::{HTTPS, PTR, RData, SVCB, SVCParam};
  use simple_dns::{CLASS, PacketFlag, QCLASS, Question, ResourceRecord};
  use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket as StdUdpSocket};

  fn make_config(rules: Vec<crate::config::Rule>) -> Config {
    Config { listen: Box::new([]), default_upstream: Box::new([]), rules, log: false }
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

  fn query(id: u16, qname: &str, qtype: TYPE) -> Packet<'static> {
    let mut query = Packet::new_query(id);
    query.set_flags(PacketFlag::RECURSION_DESIRED);
    query.questions.push(Question::new(
      name(qname).into_owned(),
      QTYPE::TYPE(qtype),
      QCLASS::CLASS(CLASS::IN),
      false,
    ));
    query
  }

  fn ipv6_ptr_name(ipv6: Ipv6Addr) -> String {
    let mut labels = Vec::with_capacity(34);
    for byte in ipv6.octets().iter().rev() {
      labels.push(format!("{:x}", byte & 0x0f));
      labels.push(format!("{:x}", byte >> 4));
    }
    labels.push("ip6".to_owned());
    labels.push("arpa".to_owned());
    labels.join(".")
  }

  #[test]
  fn adds_one_default_upstream_rdns_rule_per_prefix() {
    let prefix = "64:ff9b::".parse().unwrap();
    let mut first = make_rule(&["example.com"]);
    first.dns64_prefix = Some(prefix);
    let mut second = make_rule(&["example.net"]);
    second.dns64_prefix = Some(prefix);

    let instance = Instance::new(make_config(vec![first, second]));
    let reverse_domain = dns64::rdns_domain(prefix);
    let generated: Vec<_> = instance
      .config
      .rules
      .iter()
      .filter(|rule| rule.domains.iter().any(|domain| **domain == *reverse_domain))
      .collect();

    assert_eq!(generated.len(), 1);
    assert_eq!(generated[0].dns64_prefix, Some(prefix));
    assert!(generated[0].upstream.is_none());
    assert!(!generated[0].dns64_force_synth);
    assert!(!generated[0].strip_a);
  }

  #[test]
  fn generated_rdns_rule_only_matches_its_exact_96_bit_prefix() {
    let prefix = "64:ff9b::".parse().unwrap();
    let mut rule = make_rule(&["example.com"]);
    rule.dns64_prefix = Some(prefix);
    let instance = Instance::new(make_config(vec![rule]));

    let inside = ipv6_ptr_name("64:ff9b::c000:201".parse().unwrap());
    let outside = ipv6_ptr_name("64:ff9b:0:1::c000:201".parse().unwrap());
    assert_eq!(instance.select_rule(&name(&inside)).unwrap().dns64_prefix, Some(prefix));
    assert!(instance.select_rule(&name(&outside)).is_none());
  }

  #[test]
  fn explicit_rdns_rule_suppresses_generation_for_the_prefix() {
    let prefix = "64:ff9b::".parse().unwrap();
    let manual_upstream = "127.0.0.1:5300".parse().unwrap();
    let mut forward = make_rule(&["example.com"]);
    forward.dns64_prefix = Some(prefix);
    let mut reverse = make_rule(&["b.9.f.f.4.6.0.0.ip6.arpa"]);
    reverse.dns64_prefix = Some(prefix);
    reverse.upstream = Some(vec![manual_upstream].into_boxed_slice());

    let instance = Instance::new(make_config(vec![forward, reverse]));
    let query_name = ipv6_ptr_name("64:ff9b::c000:201".parse().unwrap());
    let selected = instance.select_rule(&name(&query_name)).unwrap();

    assert_eq!(instance.config.rules.len(), 2);
    assert_eq!(selected.upstream.as_deref(), Some(&[manual_upstream][..]));
  }

  #[test]
  fn automatically_translates_rdns_through_default_upstream() {
    let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let server = std::thread::spawn(move || {
      let mut buf = [0; transport::UDP_MAX_PACKET_SIZE];
      let (len, peer) = upstream.recv_from(&mut buf).unwrap();
      let query = Packet::parse(&buf[..len]).unwrap();
      assert_eq!(question_type(query.questions[0].qtype), TYPE::PTR);
      assert_eq!(query.questions[0].qname, name("1.2.0.192.in-addr.arpa"));

      let owner = query.questions[0].qname.clone().into_owned();
      let mut response = Packet::new_reply(query.id());
      response.set_flags(PacketFlag::RECURSION_AVAILABLE);
      response.questions.extend(query.questions.into_iter().map(Question::into_owned));
      response.answers.push(ResourceRecord::new(
        owner,
        CLASS::IN,
        300,
        RData::PTR(PTR::from(name("host.example").into_owned())),
      ));
      upstream.send_to(&response.build_bytes_vec_compressed().unwrap(), peer).unwrap();
    });

    let prefix = "64:ff9b::".parse().unwrap();
    let mut rule = make_rule(&["example.com"]);
    rule.dns64_prefix = Some(prefix);
    rule.upstream = Some(vec!["127.0.0.1:9".parse().unwrap()].into_boxed_slice());
    let instance = Instance::new(Config {
      listen: Box::new([]),
      default_upstream: vec![upstream_addr].into_boxed_slice(),
      rules: vec![rule],
      log: false,
    });
    let reverse_name = ipv6_ptr_name("64:ff9b::c000:201".parse().unwrap());
    let response = block_on(instance.handle_query(
      query(0x1234, &reverse_name, TYPE::PTR),
      "127.0.0.1:12345".parse().unwrap(),
      Transport::Udp,
    ))
    .unwrap();
    server.join().unwrap();

    let response = Packet::parse(&response).unwrap();
    assert_eq!(response.questions[0].qname, name(&reverse_name));
    assert_eq!(response.answers[0].name, name(&reverse_name));
    assert!(matches!(&response.answers[0].rdata, RData::PTR(ptr) if ptr.0 == name("host.example")));
  }

  #[test]
  fn forwards_and_mangles_https_and_svcb_responses() {
    for (qtype, dns64) in [(TYPE::HTTPS, true), (TYPE::SVCB, false)] {
      let upstream = StdUdpSocket::bind("127.0.0.1:0").unwrap();
      let upstream_addr = upstream.local_addr().unwrap();
      let server = std::thread::spawn(move || {
        let mut buf = [0; transport::UDP_MAX_PACKET_SIZE];
        let (len, peer) = upstream.recv_from(&mut buf).unwrap();
        let query = Packet::parse(&buf[..len]).unwrap();
        let owner = query.questions[0].qname.clone().into_owned();
        let mut svcb = SVCB::new(1, Name::new_unchecked(""));
        svcb.set_ipv4hint(&[u32::from("192.0.2.1".parse::<Ipv4Addr>().unwrap())]);
        let rdata = match qtype {
          TYPE::HTTPS => RData::HTTPS(HTTPS::from(svcb)),
          TYPE::SVCB => RData::SVCB(svcb),
          _ => unreachable!(),
        };

        let mut response = Packet::new_reply(query.id());
        response.set_flags(PacketFlag::RECURSION_AVAILABLE);
        response.questions.extend(query.questions.into_iter().map(Question::into_owned));
        response.answers.push(ResourceRecord::new(owner, CLASS::IN, 300, rdata));
        upstream.send_to(&response.build_bytes_vec_compressed().unwrap(), peer).unwrap();
      });

      let mut rule = make_rule(&["example.com"]);
      rule.strip_a = true;
      rule.dns64_prefix = dns64.then(|| "64:ff9b::".parse().unwrap());
      let instance = Instance::new(make_config(vec![rule]));
      let qname = name("example.com");
      let response = block_on(instance.resolve_query(
        query(0x1234, "example.com", qtype),
        &qname,
        qtype,
        instance.select_rule(&qname),
        &[upstream_addr],
        Transport::Udp,
      ))
      .unwrap();
      server.join().unwrap();

      let response = Packet::parse(&response).unwrap();
      assert_eq!(response.answers.len(), 1);
      let svcb = match &response.answers[0].rdata {
        RData::HTTPS(https) => &https.0,
        RData::SVCB(svcb) => svcb,
        _ => panic!("not a service-binding record"),
      };
      assert!(!svcb.iter_params().any(|param| matches!(param, SVCParam::Ipv4Hint(_))));
      let ipv6hints = svcb.iter_params().find_map(|param| match param {
        SVCParam::Ipv6Hint(ips) => Some(ips.clone()),
        _ => None,
      });
      let expected = dns64.then(|| vec![u128::from("64:ff9b::c000:201".parse::<Ipv6Addr>().unwrap())]);
      assert_eq!(ipv6hints, expected);
    }
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
