use anyhow::Context;
use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

const DNS_PORT: u16 = 53;

fn parse_addr(s: &str) -> Result<SocketAddr, String> {
  if let Ok(addr) = s.parse::<SocketAddr>() {
    return Ok(addr);
  }
  match s.parse::<IpAddr>() {
    Ok(ip) => Ok(SocketAddr::new(ip, DNS_PORT)),
    Err(_) => Err(format!("expected IP or socket address, got: {s}")),
  }
}

fn deserialize_one_or_many<'de, D, T>(d: D) -> Result<Box<[T]>, D::Error>
where
  D: serde::Deserializer<'de>,
  T: Deserialize<'de>,
{
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
  }

  match OneOrMany::deserialize(d)? {
    OneOrMany::One(value) => Ok(vec![value].into_boxed_slice()),
    OneOrMany::Many(values) => Ok(values.into_boxed_slice()),
  }
}

fn deserialize_socket_addr<'de, D>(d: D) -> Result<SocketAddr, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let s = Box::<str>::deserialize(d)?;
  parse_addr(&s).map_err(serde::de::Error::custom)
}

fn deserialize_socket_addrs<'de, D>(d: D) -> Result<Box<[SocketAddr]>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  #[derive(Deserialize)]
  #[serde(transparent)]
  struct Addr(#[serde(deserialize_with = "deserialize_socket_addr")] SocketAddr);

  deserialize_one_or_many::<D, Addr>(d).map(|values| {
    values
      .into_vec()
      .into_iter()
      .map(|Addr(addr)| addr)
      .collect::<Vec<_>>()
      .into_boxed_slice()
  })
}

fn deserialize_optional_socket_addrs<'de, D>(d: D) -> Result<Option<Box<[SocketAddr]>>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum OptionalOneOrMany<T> {
    One(T),
    Many(Vec<T>),
  }

  Option::<OptionalOneOrMany<Box<str>>>::deserialize(d)?
    .map(|values| match values {
      OptionalOneOrMany::One(value) => vec![value],
      OptionalOneOrMany::Many(values) => values,
    })
    .map(|values| {
      values
        .into_iter()
        .map(|value| parse_addr(&value).map_err(serde::de::Error::custom))
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
    })
    .transpose()
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

#[derive(Deserialize)]
pub struct Config {
  #[serde(deserialize_with = "deserialize_socket_addrs")]
  pub listen: Box<[SocketAddr]>,
  #[serde(deserialize_with = "deserialize_socket_addrs")]
  pub default_upstream: Box<[SocketAddr]>,
  #[serde(rename = "rule", default)]
  pub rules: Box<[Rule]>,
  #[serde(default)]
  pub log: bool,
}

#[derive(Deserialize)]
pub struct Rule {
  #[serde(deserialize_with = "deserialize_one_or_many")]
  pub domains: Box<[Box<str>]>,
  #[serde(default, deserialize_with = "deserialize_optional_socket_addrs")]
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
    config.log |= cli.verbose;
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

  #[test]
  fn deserializes_single_upstream_value() {
    let config: Config = toml::from_str(
      concat!(
        "listen = \"127.0.0.1\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "domains = \"example.com\"\n",
        "upstream = \"8.8.8.8\"\n",
      ),
    )
    .unwrap();

    assert_eq!(config.listen[0], "127.0.0.1:53".parse().unwrap());
    assert_eq!(config.default_upstream[0], "1.1.1.1:53".parse().unwrap());
    assert_eq!(config.rules[0].upstream.as_ref().unwrap()[0], "8.8.8.8:53".parse().unwrap());
  }
}
