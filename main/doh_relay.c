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

#include "doh_relay.h"

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

/* After this many consecutive DoH failures, stop offering queries to the
 * resolver for a while. Without this every lookup pays the full DoH connect
 * timeout before falling back, which starves the worker pool. */
#define DOH_FAIL_THRESHOLD   3
#define DOH_COOLDOWN_MS      60000

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

typedef struct {
    esp_http_client_handle_t client; /* owned by this worker; never shared */
    uint32_t client_gen;             /* resolver generation the client was built for */
    doh_sink_t sink;
    uint8_t resp[DNS_RESP_MAX];
} doh_worker_t;

static dns_cache_entry_t s_cache[DNS_CACHE_SLOTS];
static SemaphoreHandle_t s_cache_lock;

static QueueHandle_t s_queue;

/* Resolver endpoint, shared between the web handler and the workers. */
static char s_doh_url[DOH_URL_MAX];
static SemaphoreHandle_t s_cfg_lock;
static volatile uint32_t s_url_gen = 1;

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
    int doh_fail_streak;
    int64_t doh_off_until_ms;
} doh_ctx_t;

static doh_ctx_t s_ctx;

/*
 * Circuit breaker for the DoH path, shared by every worker and by the web
 * handler that can change the resolver. All of it goes through a lock: the
 * failure counter is a read-modify-write, and the deadline is 64-bit, which is
 * not a single store on this 32-bit core.
 */
static SemaphoreHandle_t s_breaker_lock;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static bool breaker_is_open(void)
{
    xSemaphoreTake(s_breaker_lock, portMAX_DELAY);
    bool open = now_ms() < s_ctx.doh_off_until_ms;
    xSemaphoreGive(s_breaker_lock);
    return open;
}

/* Called whenever a query succeeds, and when the resolver is changed. */
static void breaker_reset(void)
{
    xSemaphoreTake(s_breaker_lock, portMAX_DELAY);
    s_ctx.doh_fail_streak = 0;
    s_ctx.doh_off_until_ms = 0;
    xSemaphoreGive(s_breaker_lock);
}

/* Returns true when this failure was the one that tripped the breaker. */
static bool breaker_record_failure(void)
{
    bool tripped = false;
    xSemaphoreTake(s_breaker_lock, portMAX_DELAY);
    if (++s_ctx.doh_fail_streak >= DOH_FAIL_THRESHOLD) {
        s_ctx.doh_off_until_ms = now_ms() + DOH_COOLDOWN_MS;
        s_ctx.doh_fail_streak = 0;
        tripped = true;
    }
    xSemaphoreGive(s_breaker_lock);
    return tripped;
}

enum { PATH_UNKNOWN, PATH_DOH, PATH_PLAIN, PATH_SERVFAIL };

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
        if (e->qtype == qtype && e->qclass == qclass && strcmp(e->qname, qname) == 0) {
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

static void cache_store(const char *qname, uint16_t qtype, uint16_t qclass,
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

static esp_http_client_handle_t doh_client_create(doh_worker_t *w)
{
    /* esp_http_client_init parses the URL immediately and copies the pieces it
     * needs, so a stack buffer is fine here. */
    char url[DOH_URL_MAX];
    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    strncpy(url, s_doh_url, sizeof(url) - 1);
    url[sizeof(url) - 1] = '\0';
    uint32_t gen = s_url_gen;
    xSemaphoreGive(s_cfg_lock);

    const char *pin = pinned_ca_for(url);
    ESP_LOGI(TAG, "TLS trust: %s", pin != NULL ? "pinned root CA" : "system CA bundle");

    esp_http_client_config_t cfg = {
        .url = url,
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
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    w->client_gen = gen; /* only meaningful when c != NULL */
    return c;
}

/*
 * POST the raw query to the DoH resolver. Also sanity-checks that the reply
 * echoes our transaction ID and is flagged as a response.
 */
static int doh_request(doh_worker_t *w, const uint8_t *query, size_t qlen)
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
    esp_http_client_set_header(w->client, "Content-Type", "application/dns-message");
    esp_http_client_set_header(w->client, "Accept", "application/dns-message");

    esp_err_t err = esp_http_client_set_post_field(w->client, (const char *)query, (int)qlen);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_post_field failed: %s", esp_err_to_name(err));
        return -1;
    }

    w->sink.t_start = esp_timer_get_time();
    err = esp_http_client_perform(w->client);
    int64_t t_done = esp_timer_get_time();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DoH request failed: %s (%lld ms, handshake %lld ms)",
                 esp_err_to_name(err), (t_done - w->sink.t_start) / 1000,
                 w->sink.t_connected ? (w->sink.t_connected - w->sink.t_start) / 1000 : -1);
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
    int status = esp_http_client_get_status_code(w->client);
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

/* Plaintext UDP forward to whatever resolver the upstream network handed us. */
static int plain_forward(const uint8_t *query, size_t qlen, uint8_t *out, size_t cap)
{
    esp_netif_dns_info_t dns;
    if (esp_netif_get_dns_info(s_ctx.sta_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK) {
        return -1;
    }
    if (dns.ip.type != ESP_IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0) {
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
        .sin_port = htons(53),
        .sin_addr.s_addr = dns.ip.u_addr.ip4.addr,
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

    int n = -1;
    int path = PATH_SERVFAIL;

    if (((pkt[2] & 0x78) >> 3) != 0) {
        n = build_servfail(pkt, len, question_len, parsed, w->resp, sizeof(w->resp));
    } else {
        if (parsed) {
            int cached_path = PATH_UNKNOWN;
            n = cache_lookup(pkt, question_len, qname, qtype, qclass,
                             w->resp, sizeof(w->resp), &cached_path);
            if (n > 0) {
                /* Report how the answer was originally obtained, not "doh". */
                path = (cached_path == PATH_UNKNOWN) ? PATH_DOH : cached_path;
                __atomic_fetch_add((uint32_t *)&s_ctx.cached_count, 1, __ATOMIC_RELAXED);
            }
        }
        bool breaker_open = breaker_is_open();
        bool doh_allowed = s_ctx.time_synced && !breaker_open;
        const char *skip_reason = NULL;
        if (!s_ctx.time_synced) {
            skip_reason = "no clock";
        } else if (breaker_open) {
            skip_reason = "cooling down";
        }

        if (n <= 0 && doh_allowed) {
            /* Two attempts: a pooled keep-alive connection is often already
             * closed by the peer once a quiet spell passes, which surfaces as
             * ESP_ERR_HTTP_WRITE_DATA. Retrying on a brand-new socket keeps
             * that case on the encrypted path instead of silently downgrading
             * the query to plaintext. */
            for (int attempt = 0; attempt < 2 && n <= 0; attempt++) {
                /* Recycle the session if the configured resolver changed. */
                if (w->client != NULL && w->client_gen != s_url_gen) {
                    esp_http_client_cleanup(w->client);
                    w->client = NULL;
                }
                if (w->client == NULL) {
                    w->client = doh_client_create(w);
                }
                if (w->client == NULL) {
                    break;
                }

                n = doh_request(w, pkt, len);
                if (n > 0) {
                    path = PATH_DOH;
                    breaker_reset();
                    if (w->sink.t_connected != 0) {
                        __atomic_fetch_add((uint32_t *)&s_ctx.new_conn_count, 1, __ATOMIC_RELAXED);
                    } else {
                        __atomic_fetch_add((uint32_t *)&s_ctx.pooled_count, 1, __ATOMIC_RELAXED);
                    }
                } else if (attempt == 0) {
                    /* Close but do not destroy: the transport keeps the saved
                     * TLS session ticket, so the retry resumes the session
                     * rather than paying for another full handshake. Calling
                     * esp_http_client_cleanup() here would discard it. */
                    esp_http_client_close(w->client);
                    ESP_LOGD(TAG, "retrying on a resumed session");
                } else {
                    esp_http_client_cleanup(w->client);
                    w->client = NULL;
                }
            }
            if (n <= 0 && breaker_record_failure()) {
                ESP_LOGW(TAG, "DoH failing, pausing it for %d s", DOH_COOLDOWN_MS / 1000);
            }
        } else if (n <= 0 && skip_reason != NULL) {
            static bool warned[2];
            int idx = (skip_reason[0] == 'n') ? 0 : 1;
            if (!warned[idx]) {
                warned[idx] = true;
                ESP_LOGI(TAG, "DoH skipped (%s), using plaintext", skip_reason);
            }
        }
        if (n <= 0) {
            n = plain_forward(pkt, len, w->resp, sizeof(w->resp));
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
            cache_store(qname, qtype, qclass, w->resp, (size_t)n, path);
        }
    }

    s_ctx.last_path = path;

    if (n > 0) {
        sendto(s_ctx.sock, w->resp, n, 0,
               (const struct sockaddr *)&job->src, job->src_len);
    }

    static const char *names[] = { "unknown", "doh", "plain", "servfail" };
    uint32_t c = __atomic_fetch_add((uint32_t *)&s_ctx.query_count, 1, __ATOMIC_RELAXED);
    if (c < DNS_LOG_VERBOSE) {
        ESP_LOGI(TAG, "%-8s %-40s len=%d heap=%u", names[path], parsed ? qname : "<unparsed>",
                 n, (unsigned)esp_get_free_heap_size());
    } else {
        ESP_LOGD(TAG, "%-8s %-40s len=%d", names[path], parsed ? qname : "<unparsed>", n);
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
    if (changed) {
        s_url_gen++;
    }
    xSemaphoreGive(s_cfg_lock);

    if (changed) {
        /* A fresh resolver deserves a fresh breaker. */
        breaker_reset();
        s_ctx.last_path = PATH_UNKNOWN;
        ESP_LOGI(TAG, "resolver set to %s", url);
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
    s_breaker_lock = xSemaphoreCreateMutex();
    if (s_breaker_lock == NULL) {
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
}

const char *doh_relay_mode(void)
{
    if (!s_ctx.started) {
        return "off";
    }
    if (!s_ctx.time_synced) {
        return "fallback (waiting for clock)";
    }
    if (breaker_is_open()) {
        return "fallback (DoH cooling down)";
    }
    if (s_ctx.last_path == PATH_PLAIN || s_ctx.last_path == PATH_SERVFAIL) {
        return "fallback (DoH failing)";
    }
    return "doh";
}
