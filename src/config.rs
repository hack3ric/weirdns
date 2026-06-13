use anyhow::{Context, bail};
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
#[serde(transparent)]
struct SocketAddrs(#[serde(deserialize_with = "deserialize_socket_addrs")] Box<[SocketAddr]>);

#[derive(Deserialize)]
#[serde(transparent)]
struct Domains(#[serde(deserialize_with = "deserialize_one_or_many")] Box<[Box<str>]>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBody {
  listen: Option<SocketAddrs>,
  default_upstream: Option<SocketAddrs>,
  #[serde(default)]
  log: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedConfigFile {
  #[serde(flatten)]
  body: ConfigBody,
  #[serde(rename = "rule", default)]
  rules: Vec<ParsedRule>,
  #[serde(rename = "instance", default)]
  instances: Vec<InstanceRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleIncludeFile {
  #[serde(rename = "rule", default)]
  rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParsedRule {
  include: Option<PathBuf>,
  domains: Option<Domains>,
  upstream: Option<SocketAddrs>,
  dns64_prefix: Option<Ipv6Addr>,
  #[serde(default)]
  dns64_force_synth: bool,
  #[serde(default)]
  strip_a: bool,
}

enum RuleSource {
  Inline(Rule),
  Include(PathBuf),
}

#[derive(Deserialize)]
struct InstanceRef {
  include: PathBuf,
}

impl ConfigBody {
  fn has_values(&self) -> bool {
    self.listen.is_some() || self.default_upstream.is_some() || self.log
  }

  fn into_config(self) -> anyhow::Result<Config> {
    Ok(Config {
      listen: self.listen.context("missing listen")?.0,
      default_upstream: self.default_upstream.context("missing default_upstream")?.0,
      rules: Box::new([]),
      log: self.log,
    })
  }
}

impl ParsedConfigFile {
  fn into_loaded(self) -> anyhow::Result<LoadedConfigFile> {
    let ParsedConfigFile { body, rules, instances } = self;
    let has_body = body.has_values() || !rules.is_empty();
    let config = if has_body {
      Some(LoadedConfig {
        config: body.into_config()?,
        rules: rules.into_iter().map(TryInto::try_into).collect::<anyhow::Result<Vec<_>>>()?,
      })
    } else {
      None
    };
    Ok(LoadedConfigFile { config, instances })
  }
}

struct LoadedConfigFile {
  config: Option<LoadedConfig>,
  instances: Vec<InstanceRef>,
}

struct LoadedConfig {
  config: Config,
  rules: Vec<RuleSource>,
}

impl TryFrom<ParsedRule> for RuleSource {
  type Error = anyhow::Error;

  fn try_from(value: ParsedRule) -> Result<Self, Self::Error> {
    let ParsedRule { include, domains, upstream, dns64_prefix, dns64_force_synth, strip_a } = value;

    if let Some(include) = include {
      if domains.is_some() || upstream.is_some() || dns64_prefix.is_some() || dns64_force_synth || strip_a {
        bail!("rule include cannot be combined with other rule fields")
      }
      return Ok(RuleSource::Include(include));
    }

    let domains = domains.context("rule is missing domains")?.0;
    Ok(RuleSource::Inline(Rule {
      domains,
      upstream: upstream.map(|value| value.0),
      dns64_prefix,
      dns64_force_synth,
      strip_a,
    }))
  }
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

  let loaded = parse_config_file(&path)?;
  if let Some(LoadedConfig { mut config, rules }) = loaded.config {
    config.rules = expand_rule_entries(rules, &path, &mut Vec::new())?.into_boxed_slice();
    config.log |= cli.verbose;
    configs.push(config);
  }

  visited.push(path.clone());
  for instance_ref in loaded.instances {
    for include_path in resolve_include_paths(&path, &instance_ref.include)? {
      read_config_inner(cli, include_path, visited, configs)?;
    }
  }
  Ok(())
}

fn parse_config_file(path: &Path) -> anyhow::Result<LoadedConfigFile> {
  let display_path = path.display();
  let content = std::fs::read_to_string(path).with_context(|| format!("cannot open {display_path}"))?;
  let parsed: ParsedConfigFile = toml::from_str(&content).with_context(|| format!("parse error in {display_path}"))?;
  parsed.into_loaded().with_context(|| format!("parse error in {display_path}"))
}

fn parse_rule_include_file(path: &Path) -> anyhow::Result<Vec<Rule>> {
  let display_path = path.display();
  let content = std::fs::read_to_string(path).with_context(|| format!("cannot open {display_path}"))?;
  let parsed: RuleIncludeFile = toml::from_str(&content).with_context(|| format!("parse error in {display_path}"))?;
  Ok(parsed.rules)
}

fn expand_rule_entries(
  entries: Vec<RuleSource>,
  source_path: &Path,
  visited_rule_files: &mut Vec<PathBuf>,
) -> anyhow::Result<Vec<Rule>> {
  let mut rules = Vec::new();

  for entry in entries {
    match entry {
      RuleSource::Inline(rule) => rules.push(rule),
      RuleSource::Include(include) => {
        for include_path in resolve_include_paths(source_path, &include)? {
          if visited_rule_files.contains(&include_path) {
            bail!("rule include cycle detected at {}", include_path.display());
          }

          visited_rule_files.push(include_path.clone());
          rules.extend(parse_rule_include_file(&include_path)?);
          visited_rule_files.pop();
        }
      }
    }
  }

  Ok(rules)
}

fn resolve_include_paths(source_path: &Path, include: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let resolved = if include.is_absolute() {
    include.to_path_buf()
  } else {
    source_path.parent().unwrap_or_else(|| Path::new(".")).join(include)
  };

  expand_glob(&resolved)
}

fn expand_glob(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let star_count = path.as_os_str().as_encoded_bytes().iter().filter(|&&b| b == b'*').count();
  if star_count == 0 {
    return Ok(vec![path.to_path_buf()]);
  }
  if star_count > 1 {
    bail!("include pattern must contain at most one '*': {}", path.display());
  }

  let path_str = path
    .to_str()
    .with_context(|| format!("include path is not valid UTF-8: {}", path.display()))?;
  let (prefix, suffix) = path_str.split_once('*').expect("counted one star");
  let search_dir = if prefix.ends_with(std::path::MAIN_SEPARATOR) {
    PathBuf::from(prefix)
  } else {
    Path::new(prefix)
      .parent()
      .map(Path::to_path_buf)
      .unwrap_or_else(|| PathBuf::from("."))
  };
  let suffix_str = suffix.to_owned();
  let mut matches = Vec::new();

  let entries = match std::fs::read_dir(&search_dir) {
    Ok(entries) => entries,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
    Err(err) => return Err(err).with_context(|| format!("cannot open {}", search_dir.display())),
  };

  for entry in entries {
    let entry = entry.with_context(|| format!("cannot read {}", search_dir.display()))?;
    let entry_path = entry.path();
    let entry_str = match entry_path.to_str() {
      Some(value) => value,
      None => continue,
    };
    if entry_str.starts_with(prefix) && entry_str.ends_with(&suffix_str) {
      matches.push(entry_path);
    }
  }

  matches.sort();
  Ok(matches)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use std::time::{SystemTime, UNIX_EPOCH};

  fn make_cli(config: impl Into<PathBuf>) -> Cli {
    Cli { config: config.into(), verbose: false }
  }

  fn unique_root(name: &str) -> PathBuf {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("weirdns-{name}-{unique}"))
  }

  #[test]
  fn resolves_instance_includes_relative_to_parent_config() {
    let root = unique_root("config-test");
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
    let config: Config = toml::from_str(concat!(
      "listen = \"127.0.0.1\"\n",
      "default_upstream = \"1.1.1.1\"\n",
      "\n",
      "[[rule]]\n",
      "domains = \"example.com\"\n",
      "upstream = \"8.8.8.8\"\n",
    ))
    .unwrap();

    assert_eq!(config.listen[0], "127.0.0.1:53".parse().unwrap());
    assert_eq!(config.default_upstream[0], "1.1.1.1:53".parse().unwrap());
    assert_eq!(
      config.rules[0].upstream.as_ref().unwrap()[0],
      "8.8.8.8:53".parse().unwrap()
    );
  }

  #[test]
  fn expands_rule_include_file_with_multiple_rules() {
    let root = unique_root("rule-include-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    let rules = root.join("rules.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "domains = \"local.example\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"rules.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(
      &rules,
      concat!(
        "[[rule]]\n",
        "domains = \"example.com\"\n",
        "\n",
        "[[rule]]\n",
        "domains = \"example.org\"\n",
      ),
    )
    .unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    let domains: Vec<&str> = configs[0].rules.iter().map(|rule| &*rule.domains[0]).collect();
    assert_eq!(domains, vec!["local.example", "example.com", "example.org"]);

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn resolves_rule_includes_relative_to_parent_config() {
    let root = unique_root("rule-relative-test");
    let nested = root.join("rules");
    fs::create_dir_all(&nested).unwrap();

    let main = root.join("main.toml");
    let child = nested.join("child.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"rules/child.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(&child, "[[rule]]\ndomains = \"example.com\"\n").unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    assert_eq!(&*configs[0].rules[0].domains[0], "example.com");

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn preserves_inline_rule_include_order() {
    let root = unique_root("rule-order-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    let include = root.join("include.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "domains = \"before.example\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"include.toml\"\n",
        "\n",
        "[[rule]]\n",
        "domains = \"after.example\"\n",
      ),
    )
    .unwrap();
    fs::write(&include, "[[rule]]\ndomains = \"middle.example\"\n").unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    let domains: Vec<&str> = configs[0].rules.iter().map(|rule| &*rule.domains[0]).collect();
    assert_eq!(domains, vec!["before.example", "middle.example", "after.example"]);

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn rejects_mixed_rule_include_and_inline_fields() {
    let result = toml::from_str::<ParsedConfigFile>(concat!(
      "listen = \"127.0.0.1:5300\"\n",
      "default_upstream = \"1.1.1.1\"\n",
      "\n",
      "[[rule]]\n",
      "include = \"rules.toml\"\n",
      "domains = \"example.com\"\n",
    ))
    .unwrap()
    .into_loaded();

    let err = match result {
      Ok(_) => panic!("expected mixed rule include to fail"),
      Err(err) => err,
    };

    assert!(err.to_string().contains("rule include cannot be combined"));
  }

  #[test]
  fn rejects_non_rule_content_in_rule_include_file() {
    let root = unique_root("rule-invalid-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    let include = root.join("include.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"include.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(&include, "listen = \"127.0.0.1:5301\"\n").unwrap();

    let err = match read_config(&make_cli(main.display().to_string())) {
      Ok(_) => panic!("expected invalid rule include file to fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("parse error in"));

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn rejects_nested_rule_includes_in_rule_files() {
    let root = unique_root("rule-cycle-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    let a = root.join("a.toml");
    let b = root.join("b.toml");

    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"a.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(&a, "[[rule]]\ninclude = \"b.toml\"\n").unwrap();
    fs::write(&b, "[[rule]]\ninclude = \"a.toml\"\n").unwrap();

    let err = match read_config(&make_cli(main.display().to_string())) {
      Ok(_) => panic!("expected nested rule include to fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("parse error in"));

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn expands_instance_include_glob_in_lexicographic_order() {
    let root = unique_root("instance-glob-test");
    let instances = root.join("instances");
    fs::create_dir_all(&instances).unwrap();

    let main = root.join("main.toml");
    fs::write(&main, concat!("[[instance]]\n", "include = \"instances/*.toml\"\n",)).unwrap();
    fs::write(
      instances.join("b.toml"),
      "listen = \"127.0.0.1:5302\"\ndefault_upstream = \"1.0.0.2\"\n",
    )
    .unwrap();
    fs::write(
      instances.join("a.toml"),
      "listen = \"127.0.0.1:5301\"\ndefault_upstream = \"1.0.0.1\"\n",
    )
    .unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].listen[0], "127.0.0.1:5301".parse().unwrap());
    assert_eq!(configs[1].listen[0], "127.0.0.1:5302".parse().unwrap());

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn expands_rule_include_glob_in_lexicographic_order() {
    let root = unique_root("rule-glob-test");
    let rules_dir = root.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    let main = root.join("main.toml");
    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"rules/*.toml\"\n",
      ),
    )
    .unwrap();
    fs::write(rules_dir.join("20.toml"), "[[rule]]\ndomains = \"b.example\"\n").unwrap();
    fs::write(rules_dir.join("10.toml"), "[[rule]]\ndomains = \"a.example\"\n").unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    let domains: Vec<&str> = configs[0].rules.iter().map(|rule| &*rule.domains[0]).collect();
    assert_eq!(domains, vec!["a.example", "b.example"]);

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn ignores_unmatched_include_globs() {
    let root = unique_root("glob-empty-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"rules/*.toml\"\n",
        "\n",
        "[[instance]]\n",
        "include = \"instances/*.toml\"\n",
      ),
    )
    .unwrap();

    let configs = read_config(&make_cli(main.display().to_string())).unwrap();
    assert_eq!(configs.len(), 1);
    assert!(configs[0].rules.is_empty());

    fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn rejects_include_patterns_with_multiple_stars() {
    let root = unique_root("glob-invalid-test");
    fs::create_dir_all(&root).unwrap();

    let main = root.join("main.toml");
    fs::write(
      &main,
      concat!(
        "listen = \"127.0.0.1:5300\"\n",
        "default_upstream = \"1.1.1.1\"\n",
        "\n",
        "[[rule]]\n",
        "include = \"rules/*/*.toml\"\n",
      ),
    )
    .unwrap();

    let err = match read_config(&make_cli(main.display().to_string())) {
      Ok(_) => panic!("expected multi-star include to fail"),
      Err(err) => err,
    };
    assert!(err.to_string().contains("at most one '*'"));

    fs::remove_dir_all(root).unwrap();
  }
}
