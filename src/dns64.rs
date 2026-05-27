use crate::config::Rule;
use crate::transport::{Transport, resolve};
use simple_dns::rdata::{AAAA, CNAME, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const MAX_CNAME_DEPTH: usize = 11;

pub async fn handle_dns64(
  query: Packet<'_>,
  rule: &Rule,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Vec<u8>> {
  let Some(prefix) = rule.dns64_prefix else {
    anyhow::bail!("DNS64 should be enabled if this is reached")
  };
  let qname = first_query_name(&query).into_owned();

  if !rule.dns64_force_synth {
    let aaaa_resp_bytes = resolve(upstream, &query.build_bytes_vec_compressed()?, &qname, transport).await?;
    let aaaa_resp = Packet::parse(&aaaa_resp_bytes)?;

    if aaaa_resp.answers.iter().any(|rr| rr.rdata.type_code() == TYPE::AAAA) {
      if log_enabled {
        eprintln!("dns64: {qname} native=AAAA");
      }
      return Ok(aaaa_resp_bytes);
    }
  }

  let records = chase_a(&qname, query.id(), upstream, transport, log_enabled).await?;

  let mut resp = Packet::new_reply(query.id());
  resp.set_flags(PacketFlag::RECURSION_AVAILABLE);
  *resp.rcode_mut() = RCODE::NoError;
  resp.questions.extend(query.questions.into_iter().map(Question::into_owned));

  let mut n = 0;
  for rr in records {
    if rr.rdata.type_code() == TYPE::A {
      let owner = if rule.dns64_force_synth { &qname } else { &rr.name };
      if let Some(aaaa) = synthesize_aaaa(prefix, owner, &rr) {
        resp.answers.push(aaaa);
        n += 1;
      }
    } else if !rule.dns64_force_synth {
      resp.answers.push(rr);
    }
  }

  if log_enabled {
    eprintln!("dns64: {qname} synthesized={n}");
  }
  Ok(resp.build_bytes_vec_compressed()?)
}

async fn chase_a(
  name: &Name<'_>,
  id: u16,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Vec<ResourceRecord<'static>>> {
  let mut current = name.clone().into_owned();
  let mut all_records = Vec::new();

  for hop in 0..MAX_CNAME_DEPTH {
    let a_query = build_query(id, current.clone(), TYPE::A);
    let a_resp_bytes = resolve(upstream, &a_query.build_bytes_vec_compressed()?, &current, transport).await?;
    let a_resp = Packet::parse(&a_resp_bytes)?;

    let has_a = a_resp.answers.iter().any(|rr| rr.rdata.type_code() == TYPE::A);
    if has_a {
      if log_enabled && hop > 0 {
        eprintln!("dns64: {name} CNAME chain resolved at hop={hop}");
      }
      all_records.extend(a_resp.answers.into_iter().map(ResourceRecord::into_owned));
      return Ok(all_records);
    }

    let cname_target = (a_resp.answers.iter())
      .find(|rr| rr.rdata.type_code() == TYPE::CNAME)
      .and_then(|rr| match &rr.rdata {
        RData::CNAME(CNAME(target)) => Some(target),
        _ => None,
      })
      .map(|target| target.clone().into_owned());

    all_records.extend(a_resp.answers.into_iter().map(ResourceRecord::into_owned));

    if let Some(target) = cname_target {
      if log_enabled {
        eprintln!("dns64: {name} hop={hop} CNAME->{target}");
      }
      current = target;
    } else {
      if log_enabled {
        eprintln!("dns64: {name} no A or CNAME at hop={hop}");
      }
      return Ok(all_records);
    }
  }

  if log_enabled {
    eprintln!("dns64: {name} max CNAME depth ({MAX_CNAME_DEPTH}) reached");
  }
  Ok(all_records)
}

pub async fn handle_dns64_rdns(
  query: Packet<'_>,
  rule: &Rule,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Vec<u8>> {
  let Some(prefix) = rule.dns64_prefix else {
    anyhow::bail!("DNS64 should be enabled if this is reached")
  };
  let qname = first_query_name(&query).into_owned();

  let prefix_bytes = prefix.octets();
  let ipv6 = match parse_ip6_arpa_name(&qname) {
    Some(v6) if v6.octets()[..12] == prefix_bytes[..12] => v6,
    _ => {
      let resp_bytes = resolve(upstream, &query.build_bytes_vec_compressed()?, &qname, transport).await?;
      return Ok(resp_bytes);
    }
  };

  let addr_bytes = ipv6.octets();
  let ipv4 = Ipv4Addr::new(addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15]);
  let ptr_name = ipv4_ptr_name(ipv4);

  let ptr_query = build_query(query.id(), ptr_name.clone(), TYPE::PTR);
  let resp_bytes = resolve(upstream, &ptr_query.build_bytes_vec_compressed()?, &ptr_name, transport).await?;
  let resp = Packet::parse(&resp_bytes)?;
  let mut out = reply_like(&resp, query.id());

  out.questions.extend(query.questions);
  for (a, b) in [
    (&mut out.answers, resp.answers),
    (&mut out.name_servers, resp.name_servers),
    (&mut out.additional_records, resp.additional_records),
  ] {
    a.extend(b.into_iter().map(|mut rr| {
      rr.name = qname.clone();
      rr
    }))
  }

  if log_enabled {
    eprintln!("dns64_rdns: {qname} -> {ipv4}");
  }

  Ok(out.build_bytes_vec_compressed()?)
}

fn synthesize_aaaa(
  prefix: Ipv6Addr,
  name: &Name<'_>,
  a_record: &ResourceRecord<'_>,
) -> Option<ResourceRecord<'static>> {
  let a_rdata = match &a_record.rdata {
    RData::A(a) => Ipv4Addr::from(a.address),
    _ => return None,
  };

  let prefix_bytes = prefix.octets();
  let a_bytes = a_rdata.octets();

  let mut ipv6_bytes = [0u8; 16];
  ipv6_bytes[..12].copy_from_slice(&prefix_bytes[..12]);
  ipv6_bytes[12..].copy_from_slice(&a_bytes);

  let ipv6 = Ipv6Addr::from(ipv6_bytes);

  Some(ResourceRecord::new(
    name.clone().into_owned(),
    a_record.class,
    a_record.ttl,
    RData::AAAA(AAAA::from(ipv6)),
  ))
}

fn first_query_name<'a>(query: &'a Packet<'a>) -> Name<'a> {
  query
    .questions
    .first()
    .map_or_else(|| Name::new_unchecked(""), |q| q.qname.clone())
}

fn build_query(id: u16, name: Name<'_>, record_type: TYPE) -> Packet<'_> {
  let mut query = Packet::new_query(id);
  query.set_flags(PacketFlag::RECURSION_DESIRED);
  query.questions.push(Question::new(
    name,
    QTYPE::TYPE(record_type),
    QCLASS::CLASS(CLASS::IN),
    false,
  ));
  query
}

fn reply_like(src: &Packet<'_>, id: u16) -> Packet<'static> {
  let mut out = Packet::new_reply(id);
  *out.opcode_mut() = src.opcode();
  *out.rcode_mut() = src.rcode();

  let flags = [
    PacketFlag::AUTHORITATIVE_ANSWER,
    PacketFlag::TRUNCATION,
    PacketFlag::RECURSION_DESIRED,
    PacketFlag::RECURSION_AVAILABLE,
    PacketFlag::AUTHENTIC_DATA,
    PacketFlag::CHECKING_DISABLED,
  ];
  let flags = flags
    .into_iter()
    .filter(|flag| src.has_flags(*flag))
    .fold(PacketFlag::empty(), |acc, flag| acc | flag);
  out.set_flags(flags);
  out
}

fn ipv4_ptr_name(ipv4: Ipv4Addr) -> Name<'static> {
  let [a, b, c, d] = ipv4.octets();
  Name::new(&format!("{d}.{c}.{b}.{a}.in-addr.arpa"))
    .expect("valid IPv4 PTR name")
    .into_owned()
}

fn parse_ip6_arpa_name(name: &Name<'_>) -> Option<Ipv6Addr> {
  let text = name.to_string();
  let parts: Vec<_> = text.split('.').collect();
  if parts.len() != 34 || parts[32] != "ip6" || parts[33] != "arpa" {
    return None;
  }

  let mut reversed = String::with_capacity(32);
  for label in parts[..32].iter().rev() {
    if label.len() != 1 || !label.as_bytes()[0].is_ascii_hexdigit() {
      return None;
    }
    reversed.push_str(label);
  }

  let mut bytes = [0u8; 16];
  for (i, chunk) in reversed.as_bytes().chunks_exact(2).enumerate() {
    let hex = std::str::from_utf8(chunk).ok()?;
    bytes[i] = u8::from_str_radix(hex, 16).ok()?;
  }
  Some(Ipv6Addr::from(bytes))
}
