use std::net::Ipv6Addr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::{Rule, dns};

pub async fn handle_dns64(query: &Message, rule: &Rule) -> Option<Message> {
  let prefix = rule.dns64_prefix?;
  let root = Name::root();
  let qname = query.queries.first().map(|q| q.name()).unwrap_or(&root);

  let mut a_query = Message::new(query.id, MessageType::Query, OpCode::Query);
  a_query.metadata.recursion_desired = true;

  for q in &query.queries {
    a_query.add_query(hickory_proto::op::Query::query(q.name.clone(), RecordType::A));
  }

  let a_bytes = a_query.to_vec().ok()?;
  let a_resp_bytes = dns::resolve(&rule.upstream, &a_bytes, qname).await?;
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
  Some(resp)
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
