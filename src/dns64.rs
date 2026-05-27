use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use either::Either;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;

use crate::config::Rule;
use crate::transport::{Transport, resolve};

const MAX_CNAME_DEPTH: usize = 11;

pub async fn handle_dns64(
  query: Message,
  rule: &Rule,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Either<Message, Vec<u8>>> {
  let Some(prefix) = rule.dns64_prefix else {
    anyhow::bail!("DNS64 should be enabled if this is reached")
  };
  let qname = first_query_name(&query);

  if !rule.dns64_force_synth {
    let aaaa_resp_bytes = resolve(upstream, &query.to_vec()?, &qname, transport).await?;
    let aaaa_resp = Message::from_vec(&aaaa_resp_bytes)?;

    if aaaa_resp.answers.iter().any(|rr| rr.record_type() == RecordType::AAAA) {
      if log_enabled {
        eprintln!("dns64: {qname} native=AAAA");
      }
      return Ok(Either::Right(aaaa_resp_bytes));
    }
  }

  let records = chase_a(&qname, query.id, upstream, transport, log_enabled).await?;

  let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
  resp.metadata.recursion_available = true;
  resp.metadata.response_code = ResponseCode::NoError;

  for q in &query.queries {
    resp.add_query(q.clone());
  }

  let mut n = 0;
  for rr in records {
    if rr.record_type() == RecordType::A {
      let owner = if rule.dns64_force_synth { &qname } else { &rr.name };
      if let Some(aaaa) = synthesize_aaaa(prefix, owner, &rr) {
        resp.add_answer(aaaa);
        n += 1;
      }
    } else if !rule.dns64_force_synth {
      resp.add_answer(rr);
    }
  }

  if log_enabled {
    eprintln!("dns64: {qname} synthesized={n}");
  }
  Ok(Either::Left(resp))
}

async fn chase_a(
  name: &Name,
  id: u16,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Vec<Record>> {
  let mut current = name.clone();
  let mut all_records: Vec<Record> = Vec::new();

  for hop in 0..MAX_CNAME_DEPTH {
    let a_query = build_query(id, current.clone(), RecordType::A);
    let a_resp_bytes = resolve(upstream, &a_query.to_vec()?, &current, transport).await?;
    let a_resp = Message::from_vec(&a_resp_bytes)?;

    let has_a = a_resp.answers.iter().any(|rr| rr.record_type() == RecordType::A);
    if has_a {
      if log_enabled && hop > 0 {
        eprintln!("dns64: {name} CNAME chain resolved at hop={hop}");
      }
      all_records.extend(a_resp.answers);
      return Ok(all_records);
    }

    let cname_target = a_resp
      .answers
      .iter()
      .find(|rr| rr.record_type() == RecordType::CNAME)
      .and_then(extract_cname_target)
      .cloned();

    if let Some(target) = cname_target {
      if log_enabled {
        eprintln!("dns64: {name} hop={hop} CNAME->{target}");
      }
      all_records.extend(a_resp.answers);
      current = target;
    } else {
      if log_enabled {
        eprintln!("dns64: {name} no A or CNAME at hop={hop}");
      }
      all_records.extend(a_resp.answers);
      return Ok(all_records);
    }
  }

  if log_enabled {
    eprintln!("dns64: {name} max CNAME depth ({MAX_CNAME_DEPTH}) reached");
  }
  Ok(all_records)
}

fn extract_cname_target(rr: &Record) -> Option<&Name> {
  match &rr.data {
    RData::CNAME(CNAME(target)) => Some(target),
    _ => None,
  }
}

pub async fn handle_dns64_rdns(
  query: Message,
  rule: &Rule,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> anyhow::Result<Either<Message, Vec<u8>>> {
  let Some(prefix) = rule.dns64_prefix else {
    anyhow::bail!("DNS64 should be enabled if this is reached")
  };
  let qname = first_query_name(&query);

  let prefix_bytes = prefix.octets();
  let ipv6 = match qname.parse_arpa_name() {
    Ok(IpNet::V6(v6)) if v6.addr().octets()[..12] == prefix_bytes[..12] => v6.addr(),
    _ => {
      let resp_bytes = resolve(upstream, &query.to_vec()?, &qname, transport).await?;
      return Ok(Either::Right(resp_bytes));
    }
  };

  let addr_bytes = ipv6.octets();
  let ipv4 = Ipv4Addr::new(addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15]);
  let ptr_name: Name = ipv4.into();

  let ptr_query = build_query(query.id, ptr_name.clone(), RecordType::PTR);
  let resp_bytes = resolve(upstream, &ptr_query.to_vec()?, &ptr_name, transport).await?;
  let mut resp = Message::from_vec(&resp_bytes)?;
  resp.metadata.id = query.id;

  (resp.answers.iter_mut())
    .chain(resp.authorities.iter_mut())
    .chain(resp.additionals.iter_mut())
    .for_each(|rr| rr.name = qname.clone());

  if log_enabled {
    eprintln!("dns64_rdns: {qname} -> {ipv4}");
  }
  resp.queries = query.queries;

  Ok(Either::Left(resp))
}

fn synthesize_aaaa(prefix: Ipv6Addr, name: &Name, a_record: &Record) -> Option<Record> {
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

  let mut rr = Record::from_rdata(name.clone(), a_record.ttl, RData::AAAA(AAAA(ipv6)));
  rr.dns_class = a_record.dns_class;
  Some(rr)
}

fn first_query_name(query: &Message) -> Name {
  query.queries.first().map_or_else(Name::root, |q| q.name().clone())
}

fn build_query(id: u16, name: Name, record_type: RecordType) -> Message {
  let mut query = Message::new(id, MessageType::Query, OpCode::Query);
  query.metadata.recursion_desired = true;
  query.add_query(hickory_proto::op::Query::query(name, record_type));
  query
}
