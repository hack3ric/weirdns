use serde::Deserialize;
use std::net::Ipv6Addr;

#[derive(Deserialize)]
pub struct TomlConfig {
  pub listen: Option<String>,
  pub default: Option<DefaultSection>,
  pub upstream: Option<Vec<UpstreamSection>>,
}

#[derive(Deserialize)]
pub struct DefaultSection {
  pub upstream: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UpstreamSection {
  pub domains: Option<Vec<String>>,
  pub address: Option<Vec<String>>,
  pub strip_a: Option<bool>,
  pub dns64_prefix: Option<String>,
}

pub struct Upstream {
  pub domains: Vec<String>,
  pub addresses: Vec<String>,
  pub strip_a: bool,
  pub dns64_prefix: Option<Ipv6Addr>,
}

pub struct Config {
  pub listen_host: String,
  pub listen_port: u16,
  pub default_upstream: Vec<String>,
  pub upstreams: Vec<Upstream>,
}

fn parse_prefix(s: &str) -> Option<Ipv6Addr> {
  let s = s.split('/').next().unwrap_or(s);
  s.parse().ok()
}

impl Config {
  pub fn load(path: &str) -> Self {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
      eprintln!("Cannot open {}: {}", path, e);
      std::process::exit(1);
    });

    let cfg: TomlConfig = toml::from_str(&content).unwrap_or_else(|e| {
      eprintln!("Parse error in {}: {}", path, e);
      std::process::exit(1);
    });

    let mut listen_host = String::from("127.0.0.1");
    let mut listen_port = 5355u16;

    if let Some(ref listen) = cfg.listen
      && let Some(colon) = listen.rfind(':')
    {
      listen_host = listen[..colon].to_string();
      listen_port = listen[colon + 1..].parse().unwrap_or(53);
    }

    let mut default_upstream = Vec::new();
    if let Some(def) = &cfg.default
      && let Some(ref upstreams) = def.upstream
    {
      default_upstream = upstreams.clone();
    }

    if default_upstream.is_empty() {
      eprintln!("Config error: no [default] section with upstream defined");
      std::process::exit(1);
    }

    let mut upstreams = Vec::new();
    if let Some(ups) = cfg.upstream {
      for us in ups {
        let domains = us.domains.unwrap_or_default();
        let addresses = match us.address {
          Some(ref a) if !a.is_empty() => a.clone(),
          _ => continue,
        };
        if domains.is_empty() {
          continue;
        }

        let strip_a = us.strip_a.unwrap_or(false);
        let dns64_prefix = us.dns64_prefix.as_ref().and_then(|p| parse_prefix(p));

        upstreams.push(Upstream { domains, addresses, strip_a, dns64_prefix });
      }
    }

    Config { listen_host, listen_port, default_upstream, upstreams }
  }
}
