#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PKT 4096
#define MAX_UPSTREAMS 4
#define MAX_DOMAINS 16

typedef struct {
  const char *domains[MAX_DOMAINS];
  int ndomains;
  ldns_resolver *resolver;
  int strip_a;
  int dns64;
  uint8_t dns64_prefix[16];
} upstream_t;

static upstream_t upstreams[4];
static int n_upstreams = 0;
static ldns_resolver *default_upstream = NULL;

static ldns_resolver *make_resolver(const char *addr) {
  ldns_resolver *r = ldns_resolver_new();
  ldns_rdf *ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, addr);
  ldns_resolver_push_nameserver(r, ns);
  ldns_resolver_set_port(r, 53);
  ldns_resolver_set_usevc(r, 1);
  ldns_resolver_set_retry(r, 1);
  struct timeval tv = {.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC, .tv_usec = 0};
  ldns_resolver_set_timeout(r, tv);
  return r;
}

static int parse_prefix(const char *str, uint8_t prefix[16]) {
  /* parse "64:ff9b::" or "64:ff9b::/96" into 16-byte IPv6 prefix */
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
                         const char *upstream_addr, int strip_a, int dns64,
                         const char *dns64_prefix) {
  if (n_upstreams >= 4)
    return;
  upstream_t *u = &upstreams[n_upstreams++];
  for (int i = 0; i < ndomains && i < MAX_DOMAINS; i++)
    u->domains[i] = domains[i];
  u->ndomains = ndomains;
  u->resolver = make_resolver(upstream_addr);
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
  /* embed IPv4 in last 32 bits of /96 prefix */
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
  /* query upstream for A records, synthesize AAAA from them */
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

  /* copy question section */
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

int main(void) {
  const char *dns64_std_domains[] = {
      "example.com.",
      "example.org.",
      "ipv4only.arpa.",
  };
  const char *dns64_cust_domains[] = {
      "example.net.",
      "httpbin.org.",
  };

  ldns_init_random(NULL, 0);

  add_upstream(dns64_std_domains, 3, "1.1.1.1", 1, 1, "64:ff9b::");
  add_upstream(dns64_cust_domains, 2, "8.8.8.8", 1, 1, "2001:db8:64::");

  default_upstream = make_resolver("1.1.1.1");

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(5355);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }

  printf("dns64-gateway listening on 127.0.0.1:5355\n");

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
