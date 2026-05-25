use std::net::{Ipv6Addr, SocketAddr};

use either::Either;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::Rule;
use crate::dns::{self, Transport};

const MAX_CNAME_DEPTH: usize = 11;

pub async fn handle_dns64(
  query: &Message,
  rule: &Rule,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> Option<Either<Message, Vec<u8>>> {
  let prefix = rule.dns64_prefix?;
  let root = Name::root();
  let qname = query.queries.first().map(|q| q.name()).unwrap_or(&root);

  if !rule.dns64_force_synth {
    let aaaa_bytes = query.to_vec().ok()?;
    let aaaa_resp_bytes = dns::resolve(upstream, &aaaa_bytes, qname, transport, log_enabled).await?;
    let aaaa_resp = Message::from_vec(&aaaa_resp_bytes).ok()?;

    if aaaa_resp.answers.iter().any(|rr| rr.record_type() == RecordType::AAAA) {
      if log_enabled {
        eprintln!("dns64: {qname} native=AAAA");
      }
      return Some(Either::Right(aaaa_resp_bytes));
    }
  }

  let records = chase_a(qname, query.id, upstream, transport, log_enabled).await?;

  let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
  resp.metadata.recursion_available = true;
  resp.metadata.response_code = ResponseCode::NoError;

  for q in &query.queries {
    resp.add_query(q.clone());
  }

  let mut n = 0;
  for rr in records {
    if rr.record_type() == RecordType::A {
      let owner = if rule.dns64_force_synth { qname } else { &rr.name };
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
  Some(Either::Left(resp))
}

async fn chase_a(
  name: &Name,
  id: u16,
  upstream: &[SocketAddr],
  transport: Transport,
  log_enabled: bool,
) -> Option<Vec<Record>> {
  let mut current = name.clone();
  let mut all_records: Vec<Record> = Vec::new();

  for hop in 0..MAX_CNAME_DEPTH {
    let mut a_query = Message::new(id, MessageType::Query, OpCode::Query);
    a_query.metadata.recursion_desired = true;
    a_query.add_query(hickory_proto::op::Query::query(current.clone(), RecordType::A));

    let a_bytes = a_query.to_vec().ok()?;
    let a_resp_bytes = dns::resolve(upstream, &a_bytes, &current, transport, log_enabled).await?;
    let a_resp = Message::from_vec(&a_resp_bytes).ok()?;

    let has_a = a_resp.answers.iter().any(|rr| rr.record_type() == RecordType::A);
    if has_a {
      if log_enabled && hop > 0 {
        eprintln!("dns64: {name} CNAME chain resolved at hop={hop}");
      }
      all_records.extend(a_resp.answers);
      return Some(all_records);
    }

    let cname_target = a_resp.answers.iter()
      .find(|rr| rr.record_type() == RecordType::CNAME)
      .and_then(extract_cname_target)
      .cloned();

    match cname_target {
      Some(target) => {
        if log_enabled {
          eprintln!("dns64: {name} hop={hop} CNAME->{target}");
        }
        all_records.extend(a_resp.answers);
        current = target;
      }
      None => {
        if log_enabled {
          eprintln!("dns64: {name} no A or CNAME at hop={hop}");
        }
        all_records.extend(a_resp.answers);
        return Some(all_records);
      }
    }
  }

  if log_enabled {
    eprintln!("dns64: {name} max CNAME depth ({MAX_CNAME_DEPTH}) reached");
  }
  Some(all_records)
}

fn extract_cname_target(rr: &Record) -> Option<&Name> {
  match &rr.data {
    RData::CNAME(CNAME(target)) => Some(target),
    _ => None,
  }
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
