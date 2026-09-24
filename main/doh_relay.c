/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_netif.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "dns_rules.h"
#include "doh_relay.h"
#include "dot_client.h"

#define DNS_PORT             53
#define DNS_HDR_LEN          12
#define DNS_RESP_MAX         4096
#define DNS_CACHE_ENTRY_MAX  1024   /* larger answers are relayed but not cached */
#define DNS_QNAME_MAX        256

#define DNS_QUEUE_LEN        32
/* Concurrent DoH lookups. Raising this is counterproductive: a full handshake
 * is software ECC on a single core, so four workers running hands at once
 * stretched each one from ~2.0 s to ~3.8 s and the contention made bursts
 * slower, not faster. Two overlaps the network wait without fighting over the
 * CPU. */
#define DNS_WORKERS          2
#define DNS_TASK_STACK       10240  /* TLS handshake needs the headroom */
#define DNS_TASK_PRIO        5
/* Above the workers: if the reader is starved while workers chew on TLS, the
 * socket backlog overflows and lookups are lost before they are ever queued. */
#define DNS_LISTEN_PRIO      7

/* Must comfortably exceed a worst-case handshake. A full handshake is ~2 s
 * alone and can stretch to ~4 s under CPU contention; a shorter timeout turns
 * a merely slow-but-working resolver into a "failure" and trips the breaker
 * below, which drops everything to plaintext. */
#define DOH_TIMEOUT_MS       6000
#define FALLBACK_TIMEOUT_MS  1500

/* After this many consecutive failures, stop offering queries to that resolver
 * for a while. Without this every lookup pays the full connect timeout before
 * falling back, which starves the worker pool. Tracked per resolver: one
 * device's broken endpoint must not degrade everyone else's. */
#define DOH_FAIL_THRESHOLD   3
#define DOH_COOLDOWN_MS      60000

/* One resolver instance per per-device rule, plus one for the default. Keyed by
 * slot index, so a worker's set is bounded and editing a rule reuses its slot. */
#define DNS_RESOLVERS        (DNS_RULE_MAX + 1)
#define DNS_DEFAULT_SLOT     DNS_RULE_MAX

/* Report each worker's stack headroom once, after this many requests. */
#define DNS_STACK_REPORT_AFTER 4

#define DNS_CACHE_SLOTS      24
#define DNS_CACHE_TTL_MS     (120 * 1000)
#define DNS_LOG_VERBOSE      20     /* log the first N queries at INFO, then DEBUG */

static const char *TAG = "doh_relay";

/*
 * Verifying against the full CA bundle costs ~2.7 s per new TLS connection on
 * this chip (the bundle search plus the per-candidate PSA key imports), while a
 * bare TCP connect to the same host measures ~46 ms. That penalty lands on the
 * first query after every quiet period, so the resolvers we know are pinned to
 * a single root instead. Any other resolver still falls back to the bundle.
 */
extern const uint8_t gsr5_pem_start[] asm("_binary_gsr5_pem_start");

static const struct {
    const char *host;
    const char *pem;
} s_pinned_ca[] = {
    { "223.5.5.5", (const char *)gsr5_pem_start }, /* GlobalSign ECC Root CA - R5 */
};

/* Extract the host portion of an https:// URL into `out`. */
static void url_host(const char *url, char *out, size_t cap)
{
    const char *p = url;
    if (strncasecmp(p, "https://", 8) == 0) {
        p += 8;
    }
    size_t i = 0;
    while (*p != '\0' && *p != '/' && *p != ':' && i < cap - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
}

static const char *pinned_ca_for(const char *url)
{
    char host[64];
    url_host(url, host, sizeof(host));
    for (size_t i = 0; i < sizeof(s_pinned_ca) / sizeof(s_pinned_ca[0]); i++) {
        if (strcasecmp(host, s_pinned_ca[i].host) == 0) {
            return s_pinned_ca[i].pem;
        }
    }
    return NULL;
}

typedef struct {
    struct sockaddr_storage src;
    socklen_t src_len;
    uint16_t len;
    uint8_t data[1024];
} dns_job_t;

typedef struct {
    bool used;
    /* The resolver is part of the key, not just the name: two devices may be
     * pointed at different resolvers, and those can legitimately return
     * different answers for the same name. Keying on name alone would serve one
     * device's answer to the other. */
    uint8_t mode;
    char addr[DOH_URL_MAX];
    char qname[DNS_QNAME_MAX];
    uint16_t qtype;
    uint16_t qclass;
    uint16_t len;
    int64_t at_ms;
    uint8_t path; /* how this answer was obtained, so /status does not lie */
    uint8_t data[DNS_CACHE_ENTRY_MAX];
} dns_cache_entry_t;

/* Response collector handed to the HTTP event handler via user_data. */
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool overflow;
    int64_t t_start;     /* us, set just before esp_http_client_perform */
    int64_t t_connected; /* us, at HTTP_EVENT_ON_CONNECTED; 0 when the socket was reused */
    int64_t t_finish;    /* us, at HTTP_EVENT_ON_FINISH */
} doh_sink_t;

/*
 * One resolver, owned by one worker. Neither esp_http_client nor esp_tls
 * handles are shareable, so each worker keeps its own connection to each
 * resolver it serves. Instances are created lazily on first use, so a worker
 * normally holds only one or two.
 */
typedef struct {
    bool     in_use;
    uint8_t  mode;                        /* dns_mode_t */
    /* Sized for the larger of the two: a default DoH URL may be DOH_URL_MAX
     * while a per-device rule is capped at DNS_RULE_ADDR_MAX. */
    char     addr[DOH_URL_MAX];           /* URL for DoH, IP[:port] otherwise */
    esp_http_client_handle_t http;        /* DoH */
    dot_conn_t *dot;                      /* DoT */
    int      fail_streak;
    int64_t  off_until_ms;
} resolver_t;

typedef struct {
    resolver_t res[DNS_RESOLVERS];
    doh_sink_t sink;
    uint8_t resp[DNS_RESP_MAX];
} doh_worker_t;

static dns_cache_entry_t s_cache[DNS_CACHE_SLOTS];
static SemaphoreHandle_t s_cache_lock;

static QueueHandle_t s_queue;

/* The default resolver: what a device without a rule of its own gets. */
static char s_doh_url[DOH_URL_MAX];

typedef struct {
    esp_netif_t *ap_netif;
    esp_netif_t *sta_netif;
    int sock;
    bool started;
    volatile bool time_synced;
    volatile int last_path; /* 0 unknown, 1 doh, 2 plain, 3 servfail */
    volatile uint32_t query_count;
    volatile uint32_t dropped;
    volatile uint32_t cached_count;
    volatile uint32_t new_conn_count;
    volatile uint32_t pooled_count;
    volatile uint32_t fallback_count;
    volatile uint32_t servfail_count;
    volatile uint32_t dot_count;          /* answered over DoT */
    volatile uint32_t plain_rule_count;   /* answered by a plaintext rule */
} doh_ctx_t;

static doh_ctx_t s_ctx;

/*
 * Resolver selection.
 *
 * s_default is the global resolver used by any device without a rule of its
 * own - the single DoH endpoint this relay had before per-device rules existed,
 * so that behaviour is preserved as the fallback.
 *
 * s_cfg_lock guards it. It is only touched when a resolver is created or
 * compared, never per packet, and the breaker lives in the resolver itself so
 * each is independent.
 */
static SemaphoreHandle_t s_cfg_lock;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

/* Per-resolver breaker. Only ever called with the caller's own resolver_t. */
static bool breaker_is_open(const resolver_t *r)
{
    return now_ms() < r->off_until_ms;
}

static void breaker_reset(resolver_t *r)
{
    r->fail_streak = 0;
    r->off_until_ms = 0;
}

/* Returns true when this failure was the one that tripped the breaker. */
static bool breaker_record_failure(resolver_t *r)
{
    if (++r->fail_streak >= DOH_FAIL_THRESHOLD) {
        r->off_until_ms = now_ms() + DOH_COOLDOWN_MS;
        r->fail_streak = 0;
        return true;
    }
    return false;
}

enum { PATH_UNKNOWN, PATH_DOH, PATH_PLAIN, PATH_SERVFAIL, PATH_DOT };

/* ---------- packet helpers ---------- */

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * Walk a QNAME starting at `p` (which points into pkt). Writes a lowercased
 * dotted name into `out`. Returns the pointer just past the name, or NULL if
 * the name is malformed or uses compression (compression cannot legitimately
 * appear in the question section, so we simply skip caching in that case).
 */
static const uint8_t *dns_read_qname(const uint8_t *pkt, size_t pkt_len,
                                     const uint8_t *p, char *out, size_t out_sz)
{
    const uint8_t *cur = p;
    size_t oi = 0;

    for (;;) {
        if (cur >= pkt + pkt_len) {
            return NULL;
        }
        uint8_t label_len = *cur;
        if (label_len == 0) {
            cur++;
            break;
        }
        if ((label_len & 0xC0) == 0xC0 || label_len > 63) {
            return NULL;
        }
        cur++;
        if (cur + label_len > pkt + pkt_len || oi + label_len + 2 > out_sz) {
            return NULL;
        }
        for (uint8_t i = 0; i < label_len; i++) {
            out[oi++] = (char)tolower((unsigned char)cur[i]);
        }
        out[oi++] = '.';
        cur += label_len;
    }

    if (oi > 0) {
        oi--; /* drop the trailing dot */
    }
    out[oi] = '\0';
    return cur;
}

/*
 * Best-effort parse of the first (and only) question. Returns false for
 * anything unusual -- callers then relay without caching.
 *
 * `qlen_out` is the length of the QUESTION SECTION ALONE (QNAME + QTYPE +
 * QCLASS), NOT counting the 12-byte header. Callers add DNS_HDR_LEN themselves.
 * Getting this off by one header corrupts every cached reply: the question
 * re-copy below runs past the question and overwrites the start of the answer
 * section.
 */
static bool dns_parse_question(const uint8_t *pkt, size_t len,
                               char *qname, size_t qname_sz,
                               uint16_t *qtype, uint16_t *qclass, size_t *qlen_out)
{
    if (len < DNS_HDR_LEN || rd16(pkt + 4) != 1) {
        return false;
    }
    const uint8_t *q = pkt + DNS_HDR_LEN;
    const uint8_t *end = dns_read_qname(pkt, len, q, qname, qname_sz);
    if (end == NULL || end + 4 > pkt + len) {
        return false;
    }
    *qtype = rd16(end);
    *qclass = rd16(end + 2);
    *qlen_out = (size_t)((end + 4) - q);
    return true;
}

/* ---------- cache (only ever touched by worker tasks) ---------- */

static int cache_lookup(const uint8_t *query, size_t question_len,
                        uint8_t mode, const char *addr,
                        const char *qname, uint16_t qtype, uint16_t qclass,
                        uint8_t *out, size_t cap, int *path_out)
{
    int found = -1;
    int64_t now = esp_timer_get_time() / 1000;
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    for (int i = 0; i < DNS_CACHE_SLOTS; i++) {
        dns_cache_entry_t *e = &s_cache[i];
        if (!e->used) {
            continue;
        }
        if (now - e->at_ms > DNS_CACHE_TTL_MS) {
            e->used = false;
            continue;
        }
        if (e->mode == mode && strcmp(e->addr, addr) == 0 &&
                e->qtype == qtype && e->qclass == qclass && strcmp(e->qname, qname) == 0) {
            if (e->len <= cap && (size_t)e->len >= DNS_HDR_LEN + question_len) {
                memcpy(out, e->data, e->len);
                /* A stored reply still carries the transaction ID -- and any
                 * 0x20-randomised question casing -- of whichever query populated
                 * it. Clients reject a reply whose ID does not match the query
                 * they sent, so adopt the current query's ID and question section.
                 * The question is byte-for-byte the same length either way, so
                 * compression pointers in the answer section stay valid. */
                out[0] = query[0];
                out[1] = query[1];
                memcpy(out + DNS_HDR_LEN, query + DNS_HDR_LEN, question_len);
                if (path_out != NULL) {
                    *path_out = e->path;
                }
                found = e->len;
            }
            break;
        }
    }
    xSemaphoreGive(s_cache_lock);
    return found;
}

static void cache_store(uint8_t mode, const char *addr,
                        const char *qname, uint16_t qtype, uint16_t qclass,
                        const uint8_t *data, size_t len, int path)
{
    if (len > DNS_CACHE_ENTRY_MAX) {
        return;
    }
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    int slot = -1;
    int64_t oldest = INT64_MAX;
    for (int i = 0; i < DNS_CACHE_SLOTS; i++) {
        if (!s_cache[i].used) {
            slot = i;
            break;
        }
        if (s_cache[i].at_ms < oldest) {
            oldest = s_cache[i].at_ms;
            slot = i;
        }
    }
    dns_cache_entry_t *e = &s_cache[slot];
    e->mode = mode;
    snprintf(e->addr, sizeof(e->addr), "%s", addr);
    snprintf(e->qname, sizeof(e->qname), "%s", qname);
    e->qtype = qtype;
    e->qclass = qclass;
    e->len = (uint16_t)len;
    e->path = (uint8_t)path;
    memcpy(e->data, data, len);
    e->at_ms = esp_timer_get_time() / 1000;
    e->used = true;
    xSemaphoreGive(s_cache_lock);
}

void doh_relay_flush_cache(void)
{
    if (s_cache_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    memset(s_cache, 0, sizeof(s_cache));
    xSemaphoreGive(s_cache_lock);
}

/* ---------- resolvers ---------- */

static esp_err_t doh_http_event(esp_http_client_event_t *evt)
{
    doh_sink_t *sink = evt->user_data;
    if (sink != NULL && evt->event_id == HTTP_EVENT_ON_CONNECTED) {
        sink->t_connected = esp_timer_get_time();
        return ESP_OK;
    }
    if (sink != NULL && evt->event_id == HTTP_EVENT_ON_FINISH) {
        sink->t_finish = esp_timer_get_time();
        return ESP_OK;
    }
    if (evt->event_id == HTTP_EVENT_ON_DATA && sink != NULL) {
        if (sink->len + evt->data_len <= sink->cap) {
            memcpy(sink->buf + sink->len, evt->data, evt->data_len);
            sink->len += evt->data_len;
        } else {
            sink->overflow = true;
        }
    }
    return ESP_OK;
}

static esp_http_client_handle_t doh_client_create(doh_worker_t *w, resolver_t *r)
{
    /* esp_http_client_init parses the URL immediately and copies the pieces it
     * needs, so r->addr is safe to pass by pointer. */
    const char *pin = pinned_ca_for(r->addr);
    ESP_LOGI(TAG, "resolver %s: TLS trust %s", r->addr,
             pin != NULL ? "pinned root CA" : "system CA bundle");

    esp_http_client_config_t cfg = {
        .url = r->addr,
        .method = HTTP_METHOD_POST,
        .timeout_ms = DOH_TIMEOUT_MS,
        .event_handler = doh_http_event,
        .user_data = &w->sink,
        .cert_pem = pin,
        .crt_bundle_attach = (pin == NULL) ? esp_crt_bundle_attach : NULL,
        .keep_alive_enable = true,
        .disable_auto_redirect = true,
        /* A full handshake is software ECDSA verification over hardware MPI and
         * costs ~2 s on this chip (see the sdkconfig notes). Caching the session
         * ticket lets a reconnect resume instead of redoing that. */
        .save_client_session = true,
    };
    (void)w;
    return esp_http_client_init(&cfg);
}

/*
 * POST the raw query to the DoH resolver. Also sanity-checks that the reply
 * echoes our transaction ID and is flagged as a response.
 */
static int doh_request(doh_worker_t *w, resolver_t *r, const uint8_t *query, size_t qlen)
{
    w->sink.buf = w->resp;
    w->sink.cap = sizeof(w->resp);
    w->sink.len = 0;
    w->sink.overflow = false;
    w->sink.t_connected = 0;
    w->sink.t_finish = 0;

    /* Order matters: esp_http_client_set_post_field() looks up the Content-Type
     * header and returns ESP_ERR_NOT_FOUND when it is not set yet, which would
     * abort before the request is ever sent. */
    esp_http_client_set_header(r->http, "Content-Type", "application/dns-message");
    esp_http_client_set_header(r->http, "Accept", "application/dns-message");

    esp_err_t err = esp_http_client_set_post_field(r->http, (const char *)query, (int)qlen);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_post_field failed: %s", esp_err_to_name(err));
        return -1;
    }

    w->sink.t_start = esp_timer_get_time();
    err = esp_http_client_perform(r->http);
    int64_t t_done = esp_timer_get_time();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DoH %s failed: %s (%lld ms)", r->addr,
                 esp_err_to_name(err), (t_done - w->sink.t_start) / 1000);
        return -1;
    }
    /* ON_CONNECTED does not fire when the pooled socket is reused, so the
     * handshake figure is -1 there and "wait" is not measurable either. */
    bool fresh = (w->sink.t_connected != 0);
    ESP_LOGD(TAG, "%s total=%lldms%s", fresh ? "new connection" : "pooled connection",
             (t_done - w->sink.t_start) / 1000,
             fresh ? "" : "");
    if (fresh) {
        ESP_LOGD(TAG, "  tcp+tls=%lldms wait=%lldms",
                 (w->sink.t_connected - w->sink.t_start) / 1000,
                 w->sink.t_finish ? (w->sink.t_finish - w->sink.t_connected) / 1000 : -1);
    }
    int status = esp_http_client_get_status_code(r->http);
    if (status != 200) {
        ESP_LOGW(TAG, "DoH HTTP status %d", status);
        return -1;
    }
    if (w->sink.overflow || w->sink.len == 0) {
        ESP_LOGW(TAG, "DoH response empty or oversized");
        return -1;
    }
    if (w->sink.len >= DNS_HDR_LEN &&
            (w->resp[0] != query[0] || w->resp[1] != query[1] || (w->resp[2] & 0x80) == 0)) {
        ESP_LOGW(TAG, "DoH response does not match the query");
        return -1;
    }
    return (int)w->sink.len;
}

/*
 * Plaintext UDP forward. With `target` non-zero the query goes to that server,
 * which is what a per-device "plain DNS" rule asks for; with it zero the
 * upstream network's own resolver is used, as before.
 */
static int plain_forward(const uint8_t *query, size_t qlen, uint8_t *out, size_t cap,
                         uint32_t target, uint16_t port)
{
    uint32_t server = target;
    if (server == 0) {
        esp_netif_dns_info_t dns;
        if (esp_netif_get_dns_info(s_ctx.sta_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK) {
            return -1;
        }
        if (dns.ip.type != ESP_IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0) {
            return -1;
        }
        server = dns.ip.u_addr.ip4.addr;
    }
    if (server == 0) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }
    struct timeval tv = {
        .tv_sec = FALLBACK_TIMEOUT_MS / 1000,
        .tv_usec = (FALLBACK_TIMEOUT_MS % 1000) * 1000,
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(port ? port : 53),
        .sin_addr.s_addr = server,
    };

    int n = -1;
    if (sendto(sock, query, qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) >= 0) {
        n = recv(sock, out, cap, 0);
    }
    close(sock);
    return n;
}

static int build_servfail(const uint8_t *query, size_t qlen, size_t question_len,
                          bool have_question, uint8_t *out, size_t cap)
{
    if (qlen < DNS_HDR_LEN || cap < DNS_HDR_LEN) {
        return -1;
    }
    size_t total = DNS_HDR_LEN + (have_question ? question_len : 0);
    if (total > cap) {
        total = DNS_HDR_LEN;
        have_question = false;
    }
    memcpy(out, query, total);

    out[2] = (uint8_t)((query[2] & 0x01) | 0x80); /* QR=1, keep RD */
    out[3] = 0x82;                                /* RA=1, RCODE=2 SERVFAIL */
    out[4] = 0;
    out[5] = have_question ? 1 : 0;               /* QDCOUNT */
    memset(out + 6, 0, 6);                        /* AN/NS/ARCOUNT = 0 */
    return (int)total;
}

/* ---------- resolver pool ---------- */

/* "IP" or "IP:port" -> network-order address and port. Rules are validated on
 * entry, so a failure here means the rule table was corrupted, not user error. */
static bool parse_ip_port(const char *s, uint32_t *ip_out, uint16_t *port_out)
{
    /* DOH_URL_MAX, not DNS_RULE_ADDR_MAX: the caller passes a string from a
     * buffer sized for the larger of the two, and only reaches here for the IP
     * literal modes anyway. */
    char buf[DOH_URL_MAX];
    snprintf(buf, sizeof(buf), "%s", s);
    uint16_t port = (port_out != NULL) ? *port_out : 0;
    char *colon = strrchr(buf, ':');
    if (colon != NULL) {
        *colon = '\0';
        long p = strtol(colon + 1, NULL, 10);
        if (p < 1 || p > 65535) {
            return false;
        }
        port = (uint16_t)p;
    }
    unsigned a, b, c, d;
    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    if (ip_out != NULL) {
        *ip_out = htonl((a << 24) | (b << 16) | (c << 8) | d);
    }
    if (port_out != NULL) {
        *port_out = port;
    }
    return true;
}

static void resolver_teardown(resolver_t *r)
{
    if (r->http != NULL) {
        esp_http_client_cleanup(r->http);
        r->http = NULL;
    }
    if (r->dot != NULL) {
        dot_free(r->dot);
        r->dot = NULL;
    }
    r->in_use = false;
    r->fail_streak = 0;
    r->off_until_ms = 0;
}

/*
 * Fetch this worker's resolver for `slot`, creating it if needed. Keyed by slot
 * rather than by address so that editing a rule reuses the same slot and its
 * superseded connection is torn down here instead of accumulating - which is
 * what keeps each worker's resolver set bounded.
 */
static resolver_t *resolver_get(doh_worker_t *w, int slot, uint8_t mode, const char *addr)
{
    if (slot < 0 || slot >= DNS_RESOLVERS || addr == NULL || addr[0] == '\0') {
        return NULL;
    }
    resolver_t *r = &w->res[slot];
    if (r->in_use && (r->mode != mode || strcmp(r->addr, addr) != 0)) {
        resolver_teardown(r);
    }
    if (!r->in_use) {
        memset(r, 0, sizeof(*r));
        r->in_use = true;
        r->mode = mode;
        snprintf(r->addr, sizeof(r->addr), "%s", addr);
    }
    return r;
}

/*
 * Run one query through a resolver; returns the response length in w->resp, or
 * -1. Each encrypted mode retries once on a fresh connection, because a pooled
 * keep-alive is often already closed by the peer after a quiet spell and that
 * should not be counted as a resolver failure.
 */
static int resolver_query(doh_worker_t *w, resolver_t *r,
                          const uint8_t *query, size_t qlen)
{
    if (r->mode == DNS_MODE_PLAIN) {
        uint32_t ip = 0;
        uint16_t port = 53;
        if (!parse_ip_port(r->addr, &ip, &port)) {
            return -1;
        }
        return plain_forward(query, qlen, w->resp, sizeof(w->resp), ip, port);
    }

    if (r->mode == DNS_MODE_DOT) {
        if (r->dot == NULL) {
            r->dot = dot_open(r->addr);
            if (r->dot == NULL) {
                ESP_LOGW(TAG, "cannot parse DoT address '%s'", r->addr);
                return -1;
            }
        }
        int n = dot_exchange(r->dot, query, qlen, w->resp, sizeof(w->resp));
        if (n <= 0) {
            /* dot_exchange already dropped the connection; this is a retry on a
             * fresh one, keeping the saved session ticket. */
            n = dot_exchange(r->dot, query, qlen, w->resp, sizeof(w->resp));
        }
        return n;
    }

    /* DoH */
    for (int attempt = 0; attempt < 2; attempt++) {
        if (r->http == NULL) {
            r->http = doh_client_create(w, r);
            if (r->http == NULL) {
                return -1;
            }
        }
        int n = doh_request(w, r, query, qlen);
        if (n > 0) {
            return n;
        }
        if (attempt == 0) {
            /* Close but do not destroy: the transport keeps the saved TLS
             * session ticket, so the retry resumes instead of redoing the
             * ~2 s handshake. cleanup() here would discard it. */
            esp_http_client_close(r->http);
        } else {
            esp_http_client_cleanup(r->http);
            r->http = NULL;
        }
    }
    return -1;
}

/* ---------- workers ---------- */

static void handle_job(doh_worker_t *w, const dns_job_t *job)
{
    const uint8_t *pkt = job->data;
    size_t len = job->len;

    if (len < DNS_HDR_LEN || (pkt[2] & 0x80)) {
        return; /* truncated, or a response rather than a query */
    }

    char qname[DNS_QNAME_MAX];
    uint16_t qtype = 0, qclass = 0;
    size_t question_len = 0;
    bool parsed = dns_parse_question(pkt, len, qname, sizeof(qname),
                                     &qtype, &qclass, &question_len);

    /* Which resolver is this client entitled to? A per-device rule if one
     * matches the query's source address, otherwise the default - which is the
     * single global DoH endpoint, so an unconfigured device behaves exactly as
     * it did before per-device rules existed. */
    uint32_t src_ip = 0;
    if (job->src_len >= sizeof(struct sockaddr_in) &&
            ((struct sockaddr *)&job->src)->sa_family == AF_INET) {
        src_ip = ((struct sockaddr_in *)&job->src)->sin_addr.s_addr;
    }

    dns_rule_t rule;
    int slot = DNS_DEFAULT_SLOT;
    uint8_t mode = DNS_MODE_DOH;
    char addr[DOH_URL_MAX];

    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    snprintf(addr, sizeof(addr), "%s", s_doh_url);
    xSemaphoreGive(s_cfg_lock);

    if (dns_rules_lookup_ip(src_ip, &rule, &slot)) {
        mode = rule.mode;
        snprintf(addr, sizeof(addr), "%s", rule.addr);
    }

    resolver_t *res = resolver_get(w, slot, mode, addr);
    bool encrypted = (res != NULL && res->mode != DNS_MODE_PLAIN);

    int n = -1;
    int path = PATH_SERVFAIL;

    if (((pkt[2] & 0x78) >> 3) != 0) {
        n = build_servfail(pkt, len, question_len, parsed, w->resp, sizeof(w->resp));
    } else {
        if (parsed) {
            int cached_path = PATH_UNKNOWN;
            n = cache_lookup(pkt, question_len, mode, addr, qname, qtype, qclass,
                             w->resp, sizeof(w->resp), &cached_path);
            if (n > 0) {
                /* Report how the answer was originally obtained, not "doh". */
                path = (cached_path == PATH_UNKNOWN) ? PATH_DOH : cached_path;
                __atomic_fetch_add((uint32_t *)&s_ctx.cached_count, 1, __ATOMIC_RELAXED);
            }
        }

        bool breaker_open = (res != NULL) && breaker_is_open(res);
        bool encrypted_allowed = res != NULL && s_ctx.time_synced && !breaker_open;
        const char *skip_reason = NULL;
        if (res == NULL) {
            skip_reason = "no resolver";
        } else if (!s_ctx.time_synced) {
            skip_reason = "no clock";
        } else if (breaker_open) {
            skip_reason = "cooling down";
        }

        if (n <= 0 && encrypted && encrypted_allowed) {
            n = resolver_query(w, res, pkt, len);
            if (n > 0) {
                path = (res->mode == DNS_MODE_DOT) ? PATH_DOT : PATH_DOH;
                breaker_reset(res);
                if (res->mode == DNS_MODE_DOT) {
                    __atomic_fetch_add((uint32_t *)&s_ctx.dot_count, 1, __ATOMIC_RELAXED);
                } else if (w->sink.t_connected != 0) {
                    __atomic_fetch_add((uint32_t *)&s_ctx.new_conn_count, 1, __ATOMIC_RELAXED);
                } else {
                    __atomic_fetch_add((uint32_t *)&s_ctx.pooled_count, 1, __ATOMIC_RELAXED);
                }
            } else if (breaker_record_failure(res)) {
                ESP_LOGW(TAG, "resolver %s failing, pausing it for %d s",
                         res->addr, DOH_COOLDOWN_MS / 1000);
            }
        } else if (n <= 0 && encrypted && skip_reason != NULL) {
            static bool warned_no_clock, warned_other;
            bool *flag = (skip_reason[0] == 'n' && skip_reason[1] == 'o' && skip_reason[2] == ' ')
                         ? &warned_no_clock : &warned_other;
            if (!*flag) {
                *flag = true;
                ESP_LOGI(TAG, "encrypted path skipped (%s)", skip_reason);
            }
        } else if (n <= 0 && !encrypted && res != NULL) {
            /* A plaintext rule is a deliberate choice, so this is the normal
             * path for that device rather than a fallback. */
            n = resolver_query(w, res, pkt, len);
            if (n > 0) {
                path = PATH_PLAIN;
                __atomic_fetch_add((uint32_t *)&s_ctx.plain_rule_count, 1, __ATOMIC_RELAXED);
            }
        }

        /* Fall back to the upstream resolver only when the configured one could
         * not answer. For a plaintext rule that already happened above. */
        if (n <= 0 && encrypted) {
            n = plain_forward(pkt, len, w->resp, sizeof(w->resp), 0, 53);
            if (n > 0) {
                path = PATH_PLAIN;
                __atomic_fetch_add((uint32_t *)&s_ctx.fallback_count, 1, __ATOMIC_RELAXED);
            }
        }
        if (n <= 0) {
            n = build_servfail(pkt, len, question_len, parsed, w->resp, sizeof(w->resp));
            path = PATH_SERVFAIL;
            __atomic_fetch_add((uint32_t *)&s_ctx.servfail_count, 1, __ATOMIC_RELAXED);
        } else if (parsed && n <= DNS_CACHE_ENTRY_MAX) {
            cache_store(mode, addr, qname, qtype, qclass, w->resp, (size_t)n, path);
        }
    }

    s_ctx.last_path = path;

    if (n > 0) {
        sendto(s_ctx.sock, w->resp, n, 0,
               (const struct sockaddr *)&job->src, job->src_len);
    }

    static const char *names[] = { "unknown", "doh", "plain", "servfail", "dot" };
    uint32_t c = __atomic_fetch_add((uint32_t *)&s_ctx.query_count, 1, __ATOMIC_RELAXED);
    if (c < DNS_LOG_VERBOSE) {
        ESP_LOGI(TAG, "%-8s %-34s %s len=%d", names[path], parsed ? qname : "<unparsed>",
                 addr, n);
    } else {
        ESP_LOGD(TAG, "%-8s %-34s %s len=%d", names[path], parsed ? qname : "<unparsed>",
                 addr, n);
    }
}

static void dns_worker_task(void *arg)
{
    doh_worker_t *w = arg;
    dns_job_t *job = malloc(sizeof(dns_job_t));
    if (job == NULL) {
        ESP_LOGE(TAG, "worker out of memory");
        vTaskDelete(NULL);
        return;
    }
    unsigned handled = 0;
    for (;;) {
        if (xQueueReceive(s_queue, job, portMAX_DELAY) == pdTRUE) {
            handle_job(w, job);
            /* The TLS handshake is this task's stack peak, so report the
             * remaining margin once we have been through some work: a stack
             * that is too small should show up here as a small number rather
             * than as a crash later. */
            if (++handled == DNS_STACK_REPORT_AFTER) {
                ESP_LOGI(TAG, "worker stack headroom: %u bytes",
                         (unsigned)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t));
            }
        }
    }
}

static void dns_listen_task(void *arg)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    s_ctx.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_ctx.sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    if (bind(s_ctx.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind(:53) failed: errno %d", errno);
        close(s_ctx.sock);
        s_ctx.sock = -1;
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "DNS relay listening on :%d", DNS_PORT);

    dns_job_t *job = malloc(sizeof(dns_job_t));
    if (job == NULL) {
        ESP_LOGE(TAG, "listener out of memory");
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        job->src_len = sizeof(job->src);
        int len = recvfrom(s_ctx.sock, job->data, sizeof(job->data), 0,
                           (struct sockaddr *)&job->src, &job->src_len);
        if (len <= 0) {
            continue;
        }
        job->len = (uint16_t)len;
        if (xQueueSend(s_queue, job, 0) != pdTRUE) {
            /* Answering SERVFAIL beats staying silent: silence makes the client
             * wait out its own retry timer, whereas a fast failure lets it move
             * on to its next resolver immediately. */
            char qname[DNS_QNAME_MAX];
            uint16_t qtype = 0, qclass = 0;
            size_t question_len = 0;
            bool parsed = dns_parse_question(job->data, job->len, qname, sizeof(qname),
                                             &qtype, &qclass, &question_len);
            uint8_t busy[512];
            int n = build_servfail(job->data, job->len, question_len, parsed,
                                   busy, sizeof(busy));
            if (n > 0) {
                sendto(s_ctx.sock, busy, n, 0,
                       (const struct sockaddr *)&job->src, job->src_len);
            }
            s_ctx.dropped++;
            if (s_ctx.dropped <= 5) {
                ESP_LOGW(TAG, "queue full, answered SERVFAIL (%u so far)",
                         (unsigned)s_ctx.dropped);
            }
        }
    }
}

/* ---------- public API ---------- */

esp_err_t doh_relay_set_url(const char *url)
{
    if (url == NULL || strncasecmp(url, "https://", 8) != 0) {
        ESP_LOGE(TAG, "refusing resolver '%s': must be an https:// URL", url ? url : "(null)");
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(url) >= DOH_URL_MAX) {
        ESP_LOGE(TAG, "resolver URL too long");
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    bool changed = strcmp(s_doh_url, url) != 0;
    strncpy(s_doh_url, url, sizeof(s_doh_url) - 1);
    s_doh_url[sizeof(s_doh_url) - 1] = '\0';
    xSemaphoreGive(s_cfg_lock);

    if (changed) {
        /* No breaker to reset here: resolvers are keyed by address, so the next
         * query on the default slot sees the new address, tears the old
         * instance down and starts fresh - breaker included. */
        s_ctx.last_path = PATH_UNKNOWN;
        ESP_LOGI(TAG, "default resolver set to %s", url);
    }
    return ESP_OK;
}

void doh_relay_get_url(char *out, size_t cap)
{
    if (out == NULL || cap == 0 || s_cfg_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    strncpy(out, s_doh_url, cap - 1);
    out[cap - 1] = '\0';
    xSemaphoreGive(s_cfg_lock);
}

esp_err_t doh_relay_start(esp_netif_t *ap_netif, esp_netif_t *sta_netif,
                          const char *doh_url)
{
    if (s_ctx.started) {
        return ESP_OK;
    }
    s_ctx.ap_netif = ap_netif;
    s_ctx.sta_netif = sta_netif;

    s_cfg_lock = xSemaphoreCreateMutex();
    if (s_cfg_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    snprintf(s_doh_url, sizeof(s_doh_url), "%s",
             (doh_url != NULL && doh_url[0] != '\0') ? doh_url : DOH_DEFAULT_URL);
    if (strncasecmp(s_doh_url, "https://", 8) != 0) {
        ESP_LOGW(TAG, "resolver '%s' is not https, falling back to the default", s_doh_url);
        snprintf(s_doh_url, sizeof(s_doh_url), "%s", DOH_DEFAULT_URL);
    }

    s_cache_lock = xSemaphoreCreateMutex();
    if (s_cache_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    s_queue = xQueueCreate(DNS_QUEUE_LEN, sizeof(dns_job_t));
    if (s_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    for (int i = 0; i < DNS_WORKERS; i++) {
        doh_worker_t *w = calloc(1, sizeof(doh_worker_t));
        if (w == NULL) {
            return ESP_ERR_NO_MEM;
        }
        if (xTaskCreate(dns_worker_task, "doh_worker", DNS_TASK_STACK, w,
                        DNS_TASK_PRIO, NULL) != pdPASS) {
            free(w);
            return ESP_ERR_NO_MEM;
        }
    }
    if (xTaskCreate(dns_listen_task, "dns_listen", 4096, NULL,
                    DNS_LISTEN_PRIO, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    s_ctx.started = true;
    ESP_LOGI(TAG, "relay started, %d workers, upstream %s", DNS_WORKERS, s_doh_url);
    return ESP_OK;
}

void doh_relay_set_time_synced(bool synced)
{
    s_ctx.time_synced = synced;
    ESP_LOGI(TAG, "DoH %s", synced ? "enabled (clock is valid)" : "disabled (no clock)");
}

void doh_relay_get_stats(doh_stats_t *out)
{
    if (out == NULL) {
        return;
    }
    out->queries = s_ctx.query_count;
    out->cached = s_ctx.cached_count;
    out->new_conns = s_ctx.new_conn_count;
    out->pooled = s_ctx.pooled_count;
    out->fallback = s_ctx.fallback_count;
    out->servfail = s_ctx.servfail_count;
    out->drops = s_ctx.dropped;
    out->dot = s_ctx.dot_count;
    out->plain_rule = s_ctx.plain_rule_count;
}

/* Build a minimal A query for `name`. Returns the length, or 0 on failure. */
static size_t build_query(uint8_t *buf, size_t cap, const char *name, uint16_t id)
{
    size_t need = DNS_HDR_LEN + strlen(name) + 2 + 4;
    if (need > cap || strlen(name) > 253) {
        return 0;
    }
    memset(buf, 0, DNS_HDR_LEN);
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)(id & 0xFF);
    buf[2] = 0x01;                  /* RD */
    buf[5] = 1;                     /* QDCOUNT */
    size_t o = DNS_HDR_LEN;
    const char *p = name;
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t l = (dot != NULL) ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63) {
            return 0;
        }
        buf[o++] = (uint8_t)l;
        memcpy(buf + o, p, l);
        o += l;
        if (dot == NULL) {
            break;
        }
        p = dot + 1;
    }
    buf[o++] = 0;                   /* root label */
    buf[o++] = 0;
    buf[o++] = 1;                   /* QTYPE A */
    buf[o++] = 0;
    buf[o++] = 1;                   /* QCLASS IN */
    return o;
}

esp_err_t doh_relay_probe(uint8_t mode, const char *addr, const char *name,
                          char *out, size_t out_cap)
{
    if (out == NULL || out_cap == 0 || addr == NULL || name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    out[0] = '\0';

    uint8_t query[320];
    uint16_t id = (uint16_t)(esp_timer_get_time() & 0xFFFF);
    size_t qlen = build_query(query, sizeof(query), name, id);
    if (qlen == 0) {
        snprintf(out, out_cap, "bad name");
        return ESP_ERR_INVALID_ARG;
    }

    /* A throwaway worker: the probe must not disturb the resolvers the relay is
     * actually serving clients with, and it needs its own response buffer. */
    doh_worker_t *w = calloc(1, sizeof(doh_worker_t));
    if (w == NULL) {
        snprintf(out, out_cap, "out of memory");
        return ESP_ERR_NO_MEM;
    }

    resolver_t *r = resolver_get(w, DNS_DEFAULT_SLOT, mode, addr);
    if (r == NULL) {
        free(w);
        snprintf(out, out_cap, "bad address");
        return ESP_ERR_INVALID_ARG;
    }

    int64_t t0 = esp_timer_get_time();
    int n = resolver_query(w, r, query, qlen);
    int64_t dt = (esp_timer_get_time() - t0) / 1000;

    esp_err_t err;
    if (n <= 0) {
        snprintf(out, out_cap, "FAILED after %lld ms", dt);
        err = ESP_FAIL;
    } else {
        uint8_t rcode = (uint8_t)(w->resp[3] & 0x0F);
        uint16_t an = (uint16_t)((w->resp[6] << 8) | w->resp[7]);
        /* First A record, when present, so the answer can be eyeballed. */
        char ip[20] = "";
        if (rcode == 0 && an > 0) {
            for (int i = DNS_HDR_LEN; i + 4 <= n; i++) {
                if (w->resp[i] == 0 && w->resp[i + 1] == 1 && w->resp[i + 2] == 0 &&
                        w->resp[i + 3] == 1 && i + 10 + 4 <= n) {
                    uint16_t dl = (uint16_t)((w->resp[i + 8] << 8) | w->resp[i + 9]);
                    if (dl == 4) {
                        snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                                 w->resp[i + 10], w->resp[i + 11],
                                 w->resp[i + 12], w->resp[i + 13]);
                        break;
                    }
                }
            }
        }
        snprintf(out, out_cap, "ok %lld ms, %u answer(s)%s%s", dt, an,
                 ip[0] ? " " : "", ip);
        err = ESP_OK;
    }

    /* Release the throwaway connection rather than leaving it open. */
    resolver_teardown(r);
    free(w);
    return err;
}

/*
 * A single overall mode no longer describes the system: each device can be on a
 * different protocol, so this reports the *default* resolver's health, which is
 * what an unconfigured device experiences and what the settings page is about.
 */
const char *doh_relay_mode(void)
{
    if (!s_ctx.started) {
        return "off";
    }
    if (!s_ctx.time_synced) {
        return "fallback (waiting for clock)";
    }
    if (s_ctx.last_path == PATH_PLAIN || s_ctx.last_path == PATH_SERVFAIL) {
        return "fallback (resolver failing)";
    }
    if (s_ctx.last_path == PATH_DOT) {
        return "per-device (DoT)";
    }
    if (s_ctx.last_path == PATH_DOH) {
        return "doh";
    }
    return "idle";
}
