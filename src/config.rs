use anyhow::Context;
use serde::Deserialize;
use serde_with::{DeserializeAs, OneOrMany, serde_as};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

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
  config: PathBuf,

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
  instances: Vec<InstanceRef>,
}

#[derive(Deserialize)]
struct InstanceRef {
  include: PathBuf,
}

pub fn read_config(cli: &Cli) -> anyhow::Result<Vec<Config>> {
  let mut configs = Vec::new();
  read_config_inner(cli, cli.config.clone(), &mut Vec::new(), &mut configs)?;
  Ok(configs)
}

fn read_config_inner(
  cli: &Cli,
  path: PathBuf,
  visited: &mut Vec<PathBuf>,
  configs: &mut Vec<Config>,
) -> anyhow::Result<()> {
  if visited.contains(&path) {
    return Ok(());
  }

  let display_path = path.display();
  let content = std::fs::read_to_string(&path).with_context(|| format!("cannot open {display_path}"))?;
  let config_file: ConfigFile = toml::from_str(&content).with_context(|| format!("parse error in {display_path}"))?;
  if let Some(mut config) = config_file.config {
    config.enable_logging |= cli.verbose;
    configs.push(config);
  }

  let include_base = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
  visited.push(path);
  for instance_ref in config_file.instances {
    let include = Path::new(&*instance_ref.include);
    let include_path = if include.is_absolute() {
      include.to_path_buf()
    } else {
      include_base.join(include)
    };
    read_config_inner(cli, include_path, visited, configs)?;
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use std::time::{SystemTime, UNIX_EPOCH};

  fn make_cli(config: impl Into<PathBuf>) -> Cli {
    Cli { config: config.into(), verbose: false }
  }

  #[test]
  fn resolves_instance_includes_relative_to_parent_config() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("weirdns-config-test-{unique}"));
    let nested = root.join("instances");
    fs::create_dir_all(&nested).unwrap();

    let main = root.join("main.toml");
    let child = nested.join("child.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[instance]]\n",
        "include = \"instances/child.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(&child, "listen = \"127.0.0.1:5301\"\ndefault_upstream = \"1.0.0.1\"\n").unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].listen[0], "127.0.0.1:5300".parse().unwrap());
    assert_eq!(configs[1].listen[0], "127.0.0.1:5301".parse().unwrap());

    fs::remove_dir_all(root).unwrap();
  }
}
