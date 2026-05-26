use anyhow::Context;
use serde::Deserialize;
use serde_with::{DeserializeAs, OneOrMany, serde_as};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

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

/// DNS mangler for custom DNS64 behaviours
#[derive(argh::FromArgs)]
pub struct Cli {
  /// path to config file
  #[argh(option, short = 'c')]
  config: String,

  /// enable per-request verbose logging
  #[argh(switch, short = 'v')]
  verbose: bool,
}

#[serde_as]
#[derive(Deserialize)]
pub struct Config {
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  pub listen: Box<[SocketAddr]>,
  #[serde_as(as = "OneOrMany<Addr<DNS_PORT>>")]
  pub default_upstream: Box<[SocketAddr]>,
  #[serde(rename = "rule", default)]
  pub rules: Box<[Rule]>,
  #[serde(default)]
  pub enable_logging: bool,
}

#[serde_as]
#[derive(Deserialize)]
pub struct Rule {
  #[serde_as(as = "OneOrMany<_>")]
  pub domains: Box<[Box<str>]>,
  #[serde_as(as = "Option<OneOrMany<Addr<DNS_PORT>>>")]
  pub upstream: Option<Box<[SocketAddr]>>,
  pub dns64_prefix: Option<Ipv6Addr>,
  #[serde(default)]
  pub dns64_force_synth: bool,
  #[serde(default)]
  pub strip_a: bool,
}

#[derive(Deserialize)]
struct ConfigFile {
  #[serde(flatten)]
  config: Option<Config>,
  #[serde(rename = "instance", default)]
  instances: Box<[InstanceRef]>,
}

#[derive(Deserialize)]
struct InstanceRef {
  include: Box<str>,
}

pub fn read_config(cli: &Cli) -> anyhow::Result<Vec<Config>> {
  let mut configs = Vec::new();
  read_config_inner(&cli, cli.config.clone().into(), &mut Vec::new(), &mut configs)?;
  Ok(configs)
}

fn read_config_inner(
  cli: &Cli,
  path: Box<str>,
  visited: &mut Vec<Box<str>>,
  configs: &mut Vec<Config>,
) -> anyhow::Result<()> {
  if visited.contains(&path) {
    return Ok(());
  }
  let content = std::fs::read_to_string(&*path).with_context(|| format!("cannot open {path}"))?;
  let config_file: ConfigFile = toml::from_str(&content).with_context(|| format!("parse error in {path}"))?;
  if let Some(mut config) = config_file.config {
    config.enable_logging |= cli.verbose;
    configs.push(config);
  }
  visited.push(path);
  for instance_ref in config_file.instances {
    read_config_inner(cli, instance_ref.include, visited, configs)?;
  }
  Ok(())
}
