use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use hickory_proto::rr::Name;
use serde::Deserialize;
use serde_with::{DeserializeAs, OneOrMany, serde_as};

const DNS_PORT: u16 = 53;

enum Addr<const PORT: u16> {}

impl<'de, const PORT: u16> DeserializeAs<'de, SocketAddr> for Addr<PORT> {
  fn deserialize_as<D>(d: D) -> Result<SocketAddr, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = Box::<str>::deserialize(d)?;
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
pub struct Config {
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  pub listen: Box<[SocketAddr]>,
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  pub upstream: Box<[SocketAddr]>,
  #[serde(rename = "rule")]
  pub rules: Box<[Rule]>,
}

#[serde_as]
#[derive(Deserialize)]
pub struct Rule {
  #[serde_as(as = "OneOrMany<_>")]
  pub domains: Box<[Name]>,
  #[serde_as(as = "Option<OneOrMany<Addr<DNS_PORT>>>")]
  pub upstream: Option<Box<[SocketAddr]>>,
  pub dns64: Option<Dns64Rule>,
  #[serde(default)]
  pub strip_a: bool,
}

#[serde_as]
#[derive(Deserialize)]
pub struct Dns64Rule {
  pub prefix: Ipv6Addr,
  #[serde(default)]
  pub force_synth: bool,
}
