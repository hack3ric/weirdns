#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "toml.h"

#define MAX_PKT 4096
#define MAX_UPSTREAMS 16
#define MAX_DOMAINS 32
#define MAX_ADDRS 8

typedef struct {
  const char *domains[MAX_DOMAINS];
  int ndomains;
  ldns_resolver *resolver;
  int strip_a;
  int dns64;
  uint8_t dns64_prefix[16];
} upstream_t;

static upstream_t upstreams[MAX_UPSTREAMS];
static int n_upstreams = 0;
static ldns_resolver *default_upstream = NULL;
static char listen_host[64] = "127.0.0.1";
static uint16_t listen_port = 5355;

static ldns_resolver *make_resolver(const char *addrs[], int naddrs) {
  ldns_resolver *r = ldns_resolver_new();
  if (!r)
    return NULL;
  for (int i = 0; i < naddrs; i++) {
    ldns_rdf *ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, addrs[i]);
    if (ns)
      ldns_resolver_push_nameserver(r, ns);
  }
  ldns_resolver_set_port(r, 53);
  ldns_resolver_set_usevc(r, 1);
  ldns_resolver_set_retry(r, 1);
  struct timeval tv = {.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC, .tv_usec = 0};
  ldns_resolver_set_timeout(r, tv);
  return r;
}

static int parse_prefix(const char *str, uint8_t prefix[16]) {
  char buf[64];
  strncpy(buf, str, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char *slash = strchr(buf, '/');
  if (slash)
    *slash = '\0';

  ldns_rdf *r = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, buf);
  if (!r || ldns_rdf_size(r) != 16) {
    ldns_rdf_deep_free(r);
    return -1;
  }
  memcpy(prefix, ldns_rdf_data(r), 16);
  ldns_rdf_deep_free(r);
  return 0;
}

static void add_upstream(const char *domains[], int ndomains,
                         const char *upstream_addrs[], int naddrs,
                         int strip_a, int dns64,
                         const char *dns64_prefix) {
  if (n_upstreams >= MAX_UPSTREAMS)
    return;
  upstream_t *u = &upstreams[n_upstreams++];
  for (int i = 0; i < ndomains && i < MAX_DOMAINS; i++)
    u->domains[i] = domains[i];
  u->ndomains = ndomains;
  u->resolver = make_resolver(upstream_addrs, naddrs);
  u->strip_a = strip_a;
  u->dns64 = dns64;
  if (dns64 && dns64_prefix)
    parse_prefix(dns64_prefix, u->dns64_prefix);
}

static int domain_matches(const char *qname, const char *domain) {
  size_t qlen = strlen(qname);
  size_t dlen = strlen(domain);
  if (dlen > qlen)
    return 0;
  return strcasecmp(qname + qlen - dlen, domain) == 0;
}

static upstream_t *select_upstream(const char *qname) {
  for (int i = 0; i < n_upstreams; i++) {
    for (int j = 0; j < upstreams[i].ndomains; j++) {
      if (domain_matches(qname, upstreams[i].domains[j]))
        return &upstreams[i];
    }
  }
  return NULL;
}

static ldns_rr *synthesize_aaaa(ldns_rr *a_rr, const uint8_t prefix[16]) {
  ldns_rdf *a_rdf = ldns_rr_rdf(a_rr, 0);
  if (!a_rdf || ldns_rdf_size(a_rdf) != 4)
    return NULL;

  uint8_t ipv6[16];
  memcpy(ipv6, prefix, 12);
  memcpy(ipv6 + 12, ldns_rdf_data(a_rdf), 4);

  ldns_rdf *aaaa_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA, 16, ipv6);
  if (!aaaa_rdf)
    return NULL;

  ldns_rr *aaaa_rr = ldns_rr_new();
  ldns_rr_set_type(aaaa_rr, LDNS_RR_TYPE_AAAA);
  ldns_rr_set_class(aaaa_rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_ttl(aaaa_rr, ldns_rr_ttl(a_rr));
  ldns_rr_set_owner(aaaa_rr, ldns_rdf_clone(ldns_rr_owner(a_rr)));
  ldns_rr_push_rdf(aaaa_rr, aaaa_rdf);

  return aaaa_rr;
}

static ldns_pkt *dns64_resolve_aaaa(upstream_t *u, ldns_pkt *query) {
  ldns_pkt *a_query = ldns_pkt_clone(query);
  ldns_rr_list *qsection = ldns_pkt_question(a_query);
  ldns_rr *qrr = ldns_rr_list_rr(qsection, 0);
  ldns_rr_set_type(qrr, LDNS_RR_TYPE_A);

  ldns_pkt *a_resp = NULL;
  ldns_status st = ldns_resolver_send_pkt(&a_resp, u->resolver, a_query);
  ldns_pkt_free(a_query);

  ldns_pkt *resp = ldns_pkt_new();
  ldns_pkt_set_id(resp, ldns_pkt_id(query));
  ldns_pkt_set_qr(resp, 1);
  ldns_pkt_set_ra(resp, 1);
  ldns_pkt_set_opcode(resp, LDNS_PACKET_QUERY);
  ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);

  ldns_rr_list *orig_q = ldns_pkt_question(query);
  for (size_t i = 0; i < ldns_rr_list_rr_count(orig_q); i++)
    ldns_pkt_push_rr(resp, LDNS_SECTION_QUESTION,
                     ldns_rr_clone(ldns_rr_list_rr(orig_q, i)));

  if (st == LDNS_STATUS_OK && a_resp) {
    ldns_rr_list *answers = ldns_pkt_answer(a_resp);
    for (size_t i = 0; i < ldns_rr_list_rr_count(answers); i++) {
      ldns_rr *rr = ldns_rr_list_rr(answers, i);
      if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_A) {
        ldns_rr *aaaa = synthesize_aaaa(rr, u->dns64_prefix);
        if (aaaa)
          ldns_pkt_push_rr(resp, LDNS_SECTION_ANSWER, aaaa);
      }
    }
    ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(ldns_pkt_answer(resp)));
  }
  ldns_pkt_free(a_resp);
  return resp;
}

static int strip_a_records(ldns_pkt *pkt) {
  ldns_rr_list *answer = ldns_pkt_answer(pkt);
  if (!answer)
    return 0;

  ldns_rr_list *filtered = ldns_rr_list_new();
  size_t count = ldns_rr_list_rr_count(answer);

  for (size_t i = 0; i < count; i++) {
    ldns_rr *rr = ldns_rr_list_rr(answer, i);
    if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_A)
      ldns_rr_list_push_rr(filtered, ldns_rr_clone(rr));
  }

  ldns_rr_list_deep_free(answer);
  ldns_pkt_set_answer(pkt, filtered);
  ldns_pkt_set_ancount(pkt, ldns_rr_list_rr_count(filtered));
  return (int)(count - ldns_rr_list_rr_count(filtered));
}

static int serve(int sock, ldns_pkt *query, struct sockaddr_in *client,
                 socklen_t client_len) {
  ldns_rdf *qname_rdf =
      ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(query), 0));
  char *qname = ldns_rdf2str(qname_rdf);
  ldns_rr_type qtype =
      ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_question(query), 0));

  upstream_t *up = select_upstream(qname);
  ldns_pkt *response = NULL;

  if (up && up->dns64 && qtype == LDNS_RR_TYPE_AAAA) {
    response = dns64_resolve_aaaa(up, query);
  } else {
    ldns_resolver *resolver = up ? up->resolver : default_upstream;
    ldns_status st = ldns_resolver_send_pkt(&response, resolver, query);
    if (st != LDNS_STATUS_OK || !response) {
      fprintf(stderr, "resolve failed for %s\n", qname);
      free(qname);
      return -1;
    }
    ldns_pkt_set_id(response, ldns_pkt_id(query));
    if (up && up->strip_a)
      strip_a_records(response);
  }

  if (!response) {
    free(qname);
    return -1;
  }

  uint8_t *wire = NULL;
  size_t wire_len = 0;
  if (ldns_pkt2wire(&wire, response, &wire_len) != LDNS_STATUS_OK) {
    free(qname);
    ldns_pkt_free(response);
    return -1;
  }

  sendto(sock, wire, wire_len, 0, (struct sockaddr *)client, client_len);
  free(wire);
  free(qname);
  ldns_pkt_free(response);
  return 0;
}

static void config_load(const char *path) {
  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "Cannot open %s: ", path);
    perror("");
    exit(1);
  }
  char errbuf[200];
  toml_table_t *conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
  fclose(fp);
  if (!conf) {
    fprintf(stderr, "Parse error in %s: %s\n", path, errbuf);
    exit(1);
  }

  {
    toml_datum_t d = toml_string_in(conf, "listen");
    if (d.ok) {
      char *colon = strrchr(d.u.s, ':');
      if (colon) {
        *colon = '\0';
        strncpy(listen_host, d.u.s, sizeof(listen_host) - 1);
        listen_host[sizeof(listen_host) - 1] = '\0';
        listen_port = (uint16_t)atoi(colon + 1);
        if (listen_port == 0)
          listen_port = 53;
      }
      free(d.u.s);
    }
  }

  {
    toml_table_t *def = toml_table_in(conf, "default");
    if (def) {
      toml_array_t *arr = toml_array_in(def, "upstream");
      if (arr) {
        int n = toml_array_nelem(arr);
        const char *addrs[MAX_ADDRS];
        int naddr = 0;
        for (int i = 0; i < n && naddr < MAX_ADDRS; i++) {
          toml_datum_t d = toml_string_at(arr, i);
          if (d.ok) {
            addrs[naddr++] = strdup(d.u.s);
            free(d.u.s);
          }
        }
        if (naddr > 0) {
          default_upstream = make_resolver(addrs, naddr);
          for (int i = 0; i < naddr; i++)
            free((void *)addrs[i]);
        }
      }
    }
  }

  {
    toml_array_t *ups = toml_array_in(conf, "upstream");
    if (ups) {
      int n = toml_array_nelem(ups);
      for (int i = 0; i < n; i++) {
        toml_table_t *t = toml_table_at(ups, i);
        if (!t)
          continue;

        const char *dom_arr[MAX_DOMAINS];
        int ndom = 0;
        {
          toml_array_t *darr = toml_array_in(t, "domains");
          if (darr) {
            int nd = toml_array_nelem(darr);
            for (int j = 0; j < nd && ndom < MAX_DOMAINS; j++) {
              toml_datum_t d = toml_string_at(darr, j);
              if (d.ok) {
                dom_arr[ndom++] = strdup(d.u.s);
                free(d.u.s);
              }
            }
          }
        }
        if (ndom == 0)
          continue;

        const char *addr_arr[MAX_ADDRS];
        int naddr = 0;
        {
          toml_array_t *aarr = toml_array_in(t, "address");
          if (aarr) {
            int na = toml_array_nelem(aarr);
            for (int j = 0; j < na && naddr < MAX_ADDRS; j++) {
              toml_datum_t d = toml_string_at(aarr, j);
              if (d.ok) {
                addr_arr[naddr++] = strdup(d.u.s);
                free(d.u.s);
              }
            }
          }
        }
        if (naddr == 0) {
          for (int j = 0; j < ndom; j++)
            free((void *)dom_arr[j]);
          continue;
        }

        int strip_a = false;
        {
          toml_datum_t d = toml_bool_in(t, "strip_a");
          if (d.ok)
            strip_a = d.u.b;
        }

        int dns64_enabled = 0;
        const char *prefix_str = NULL;
        {
          toml_datum_t d = toml_string_in(t, "dns64_prefix");
          if (d.ok && d.u.s[0] != '\0') {
            uint8_t tmp[16];
            if (parse_prefix(d.u.s, tmp) == 0) {
              dns64_enabled = 1;
              prefix_str = d.u.s;
            }
          }
          add_upstream(dom_arr, ndom, addr_arr, naddr, strip_a,
                       dns64_enabled, prefix_str);
          if (d.ok)
            free(d.u.s);
        }

        for (int j = 0; j < naddr; j++)
          free((void *)addr_arr[j]);
      }
    }
  }

  if (!default_upstream) {
    fprintf(stderr, "Config error: no [default] section with upstream defined\n");
    exit(1);
  }

  toml_free(conf);
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s [-c config.toml]\n", prog);
  fprintf(stderr, "  -c PATH   path to config file (default: weirdns.toml)\n");
  fprintf(stderr, "  -h        show this help\n");
}

int main(int argc, char *argv[]) {
  const char *config_path = "weirdns.toml";
  int opt;

  while ((opt = getopt(argc, argv, "c:h")) != -1) {
    switch (opt) {
    case 'c':
      config_path = optarg;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  ldns_init_random(NULL, 0);
  config_load(config_path);

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(listen_host);
  addr.sin_port = htons(listen_port);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("listening on %s:%u\n", listen_host, listen_port);

  for (;;) {
    uint8_t buf[MAX_PKT];
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&client,
                         &client_len);
    if (n < 0) {
      perror("recvfrom");
      continue;
    }

    ldns_pkt *query = NULL;
    if (ldns_wire2pkt(&query, buf, n) != LDNS_STATUS_OK)
      continue;

    serve(sock, query, &client, client_len);
    ldns_pkt_free(query);
  }

  close(sock);
  return 0;
}
