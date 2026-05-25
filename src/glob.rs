use fqdn::{FQDN, Fqdn};

#[derive(Clone, Debug)]
pub(crate) enum LabelPattern {
  Literal(Box<[u8]>),
  AnyLabel,
  Glob(Box<[u8]>),
}

#[derive(Clone, Debug)]
pub(crate) struct GlobValue {
  pub prefix: Box<[LabelPattern]>,
  pub rule: usize,
}

impl GlobValue {
  pub fn matches(&self, query: &FQDN, suffix: &Fqdn) -> bool {
    let query_labels = fqdn_labels(query);
    let suffix_depth = suffix.depth();

    if query_labels.len() < suffix_depth + self.prefix.len() {
      return false;
    }

    let remaining = query_labels.len() - suffix_depth;
    for i in 0..self.prefix.len() {
      if !label_matches(&self.prefix[i], query_labels[remaining - 1 - i]) {
        return false;
      }
    }
    true
  }
}

#[derive(Clone, Default)]
pub(crate) struct RuleValue {
  pub exact: Option<usize>,
  pub globs: Vec<GlobValue>,
}

pub(crate) fn contains_glob(domain: &str) -> bool {
  domain.contains('*') || domain.contains('?')
}

pub(crate) fn parse_domain_pattern(domain: &str) -> Option<(FQDN, Box<[LabelPattern]>)> {
  let domain = domain.strip_suffix('.').unwrap_or(domain);
  let labels: Vec<&str> = domain.split('.').collect();

  let mut suffix_start = labels.len();
  for i in (0..labels.len()).rev() {
    if labels[i].contains(|c| c == '*' || c == '?') {
      suffix_start = i + 1;
      break;
    }
  }

  let suffix = if suffix_start >= labels.len() {
    FQDN::default()
  } else {
    let s = labels[suffix_start..].join(".");
    FQDN::from_ascii_str(&s).ok()?
  };

  let prefix: Box<[LabelPattern]> =
    labels[..suffix_start].iter().map(|l| parse_label(l)).rev().collect();

  Some((suffix, prefix))
}

fn fqdn_labels(fqdn: &FQDN) -> Vec<&[u8]> {
  let bytes = fqdn.as_bytes();
  let mut labels = Vec::new();
  let mut pos = 0;
  while pos < bytes.len() && bytes[pos] != 0 {
    let len = bytes[pos] as usize;
    labels.push(&bytes[pos + 1..pos + 1 + len]);
    pos += 1 + len;
  }
  labels
}

fn label_matches(pattern: &LabelPattern, label: &[u8]) -> bool {
  match pattern {
    LabelPattern::Literal(lit) => lit.as_ref() == label,
    LabelPattern::AnyLabel => true,
    LabelPattern::Glob(pat) => glob_match(pat, label),
  }
}

fn glob_match(pat: &[u8], input: &[u8]) -> bool {
  let m = input.len();
  // DNS labels are max 63 octets (RFC 1035), so 64 is sufficient
  let mut dp = [false; 64];
  dp[0] = true;

  for &pc in pat {
    let mut next = [false; 64];
    if pc == b'*' {
      next[0] = dp[0];
      for j in 1..=m {
        next[j] = dp[j] || next[j - 1];
      }
    } else {
      for j in 1..=m {
        if pc == b'?' || pc == input[j - 1] {
          next[j] = dp[j - 1];
        }
      }
    }
    dp = next;
  }

  dp[m]
}

fn parse_label(label: &str) -> LabelPattern {
  if label == "*" {
    LabelPattern::AnyLabel
  } else if label.contains(|c| c == '*' || c == '?') {
    LabelPattern::Glob(label.to_ascii_lowercase().into_bytes().into())
  } else {
    LabelPattern::Literal(label.to_ascii_lowercase().into_bytes().into())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn glob_matches(pattern: &str, query: &str) -> bool {
    let (suffix, prefix) = parse_domain_pattern(pattern).expect("parse pattern");
    let query_fqdn = FQDN::from_ascii_str(query).expect("parse query");
    let suffix_ref: &Fqdn = suffix.as_ref();
    let gv = GlobValue { prefix, rule: 0 };
    gv.matches(&query_fqdn, suffix_ref)
  }

  #[test]
  fn exact_no_glob() {
    assert!(contains_glob("example.com") == false);
    assert!(contains_glob("*.example.com"));
    assert!(contains_glob("prefix-*-suffix.example.com"));
  }

  #[test]
  fn literal_labels_only_suffix_is_full_domain() {
    let (suffix, prefix) = parse_domain_pattern("*-a.*-b.example.com").unwrap();
    assert_eq!(suffix.as_bytes(), FQDN::from_ascii_str("example.com").unwrap().as_bytes());
    assert_eq!(prefix.len(), 2);
    assert!(matches!(&prefix[0], LabelPattern::Glob(_))); // *-b (closest to suffix)
    assert!(matches!(&prefix[1], LabelPattern::Glob(_))); // *-a (leftmost)
  }

  #[test]
  fn any_label_wildcard() {
    let (suffix, prefix) = parse_domain_pattern("*.example.com").unwrap();
    assert_eq!(suffix.as_bytes(), FQDN::from_ascii_str("example.com").unwrap().as_bytes());
    assert_eq!(prefix.len(), 1);
    assert!(matches!(&prefix[0], LabelPattern::AnyLabel));
  }

  #[test]
  fn pattern_all_glob_is_root_suffix() {
    let (suffix, prefix) = parse_domain_pattern("*-a.*-b").unwrap();
    assert_eq!(suffix.as_bytes(), FQDN::default().as_bytes());
    assert_eq!(prefix.len(), 2);
  }

  #[test]
  fn single_char_question_mark() {
    let (_suffix, prefix) = parse_domain_pattern("app-?.example.com").unwrap();
    assert_eq!(prefix.len(), 1);
    assert!(matches!(&prefix[0], LabelPattern::Glob(_)));
    let pat_bytes = match &prefix[0] {
      LabelPattern::Glob(b) => b.as_ref(),
      _ => panic!(),
    };
    assert_eq!(pat_bytes, b"app-?");
  }

  #[test]
  fn match_exact_literal_subdomain() {
    assert!(glob_matches("example.com", "example.com"));
    assert!(glob_matches("example.com", "sub.example.com"));
  }

  #[test]
  fn match_single_wildcard_label() {
    assert!(glob_matches("*.example.com", "foo.example.com"));
    assert!(glob_matches("*.example.com", "bar.example.com"));
    // *.example.com matches subdomains too (consistent with trie suffix matching)
    assert!(glob_matches("*.example.com", "sub.foo.example.com"));
  }

  #[test]
  fn reject_wildcard_too_few_labels() {
    assert!(!glob_matches("*.*.example.com", "foo.example.com"));
  }

  #[test]
  fn match_two_wildcard_labels() {
    assert!(glob_matches("*.*.example.com", "foo.bar.example.com"));
    assert!(glob_matches("*.*.example.com", "a.b.c.example.com"));
  }

  #[test]
  fn match_with_literal_labels_mixed() {
    assert!(glob_matches("prefix-*-suffix.example.com", "prefix-123-suffix.example.com"));
    assert!(glob_matches("prefix-*-suffix.example.com", "prefix-hello-suffix.example.com"));
    assert!(!glob_matches("prefix-*-suffix.example.com", "other-123-suffix.example.com"));
    // * can match any chars within a label, including hyphens
    assert!(glob_matches("prefix-*-suffix.example.com", "prefix-abc-def-suffix.example.com"));
  }

  #[test]
  fn match_question_mark() {
    assert!(glob_matches("app-?.example.com", "app-1.example.com"));
    assert!(glob_matches("app-?.example.com", "app-x.example.com"));
    assert!(!glob_matches("app-?.example.com", "app-12.example.com"));
    assert!(!glob_matches("app-?.example.com", "app-.example.com"));
  }

  #[test]
  fn match_user_example() {
    // chatgpt-async-webps-prod-someid-123.webpubsub.azure.com against
    // chatgpt-async-webps-prod-*-*.webpubsub.azure.com
    assert!(glob_matches(
      "chatgpt-async-webps-prod-*-*.webpubsub.azure.com",
      "chatgpt-async-webps-prod-someid-123.webpubsub.azure.com"
    ));
    assert!(!glob_matches(
      "chatgpt-async-webps-prod-*-*.webpubsub.azure.com",
      "other-prefix-someid-123.webpubsub.azure.com"
    ));
  }

  #[test]
  fn mixed_literal_and_wildcard() {
    // Queries the trie would route to suffix "c.example.com":
    assert!(glob_matches("a.*.c.example.com", "a.foo.c.example.com"));
    assert!(glob_matches("a.*.c.example.com", "a.bar.c.example.com"));
    assert!(glob_matches("a.*.c.example.com", "x.a.foo.c.example.com"));
    // Literal label mismatch in prefix:
    assert!(!glob_matches("a.*.c.example.com", "x.y.z.example.com"));
  }

  #[test]
  fn glob_match_unit() {
    // Test the raw glob_match function
    assert!(glob_match(b"*-*", b"someid-123"));
    assert!(glob_match(b"prefix-*-suffix", b"prefix-hello-suffix"));
    assert!(!glob_match(b"prefix-*-suffix", b"other-hello-suffix"));
    assert!(glob_match(b"*-a", b"foo-a"));
    assert!(!glob_match(b"*-a", b"foo-b"));
    assert!(glob_match(b"?at", b"cat"));
    assert!(!glob_match(b"?at", b"at"));
    assert!(glob_match(b"*", b""));
    assert!(glob_match(b"*", b"anything"));
    assert!(glob_match(b"a*b", b"ab"));
    assert!(glob_match(b"a*b", b"axxxxb"));
    assert!(!glob_match(b"a*b", b"ac"));
    assert!(glob_match(b"a?b", b"axb"));
    assert!(!glob_match(b"a?b", b"ab"));
    assert!(!glob_match(b"a?b", b"axxb"));
  }

  #[test]
  fn case_insensitive() {
    // Patterns are lowercased; queries are already lowercased by FQDN
    assert!(glob_matches("Foo*.example.COM", "foo123.example.com"));
    assert!(glob_matches("a.?b.Example.Com", "a.cB.example.com"));
  }

  #[test]
  fn root_suffix_wildcard() {
    // Pattern is just "*" → matches anything with at least 1 label
    assert!(glob_matches("*", "foo.com"));
    assert!(glob_matches("*", "example.com"));
    assert!(glob_matches("*", "com"));
  }
}

