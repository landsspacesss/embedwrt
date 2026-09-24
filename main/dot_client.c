/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_crt_bundle.h"
#include "esp_tls.h"

#include "dot_client.h"

#define DOT_DEFAULT_PORT 853
#define DOT_TIMEOUT_MS   6000

static const char *TAG = "dot";

struct dot_conn {
    char host[64];
    int  port;
    esp_tls_t *tls;
    esp_tls_client_session_t *session;   /* carried across reconnects */
};

dot_conn_t *dot_open(const char *host_port)
{
    if (host_port == NULL || host_port[0] == '\0') {
        return NULL;
    }

    dot_conn_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }

    snprintf(c->host, sizeof(c->host), "%s", host_port);
    c->port = DOT_DEFAULT_PORT;
    char *colon = strrchr(c->host, ':');
    if (colon != NULL) {
        *colon = '\0';
        long p = strtol(colon + 1, NULL, 10);
        if (p < 1 || p > 65535) {
            free(c);
            return NULL;
        }
        c->port = (int)p;
    }

    /* IPv4 literal only: see the note in the header. */
    unsigned a, b, cc, d;
    if (sscanf(c->host, "%u.%u.%u.%u", &a, &b, &cc, &d) != 4 ||
            a > 255 || b > 255 || cc > 255 || d > 255) {
        free(c);
        return NULL;
    }
    return c;
}

void dot_disconnect(dot_conn_t *c)
{
    if (c == NULL || c->tls == NULL) {
        return;
    }
    /* Retrieve the ticket before tearing the connection down - there is no
     * close-that-keeps-the-session call, and destroying the handle would take
     * the ticket with it. Mirroring IDF's own transport_ssl.c: release the old
     * one, take the current one. */
    esp_tls_free_client_session(c->session);
    c->session = esp_tls_get_client_session(c->tls);

    esp_tls_conn_destroy(c->tls);
    c->tls = NULL;
}

void dot_free(dot_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    dot_disconnect(c);
    esp_tls_free_client_session(c->session);
    c->session = NULL;
    free(c);
}

bool dot_is_connected(const dot_conn_t *c)
{
    return c != NULL && c->tls != NULL;
}

static bool ensure_connected(dot_conn_t *c)
{
    if (c->tls != NULL) {
        return true;
    }

    esp_tls_cfg_t cfg = {
        .timeout_ms = DOT_TIMEOUT_MS,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .client_session = c->session,   /* NULL on the first connect */
    };

    c->tls = esp_tls_init();
    if (c->tls == NULL) {
        ESP_LOGE(TAG, "esp_tls_init failed");
        return false;
    }

    if (esp_tls_conn_new_sync(c->host, strlen(c->host), c->port, &cfg, c->tls) != 1) {
        ESP_LOGW(TAG, "connect to %s:%d failed", c->host, c->port);
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
        return false;
    }
    ESP_LOGD(TAG, "connected to %s:%d%s", c->host, c->port,
             c->session ? " (resumed)" : "");
    return true;
}

static bool write_all(dot_conn_t *c, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = esp_tls_conn_write(c->tls, buf + off, len - off);
        if (n <= 0) {
            ESP_LOGW(TAG, "write failed at %u/%u", (unsigned)off, (unsigned)len);
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool read_all(dot_conn_t *c, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = esp_tls_conn_read(c->tls, buf + off, len - off);
        if (n <= 0) {
            ESP_LOGW(TAG, "read failed at %u/%u", (unsigned)off, (unsigned)len);
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

int dot_exchange(dot_conn_t *c, const uint8_t *query, size_t qlen,
                 uint8_t *out, size_t cap)
{
    if (c == NULL || query == NULL || out == NULL || qlen == 0 || qlen > 65535) {
        return -1;
    }
    if (!ensure_connected(c)) {
        return -1;
    }

    /* RFC 7858 section 3.3: 2-byte big-endian length, then the DNS message. */
    uint8_t hdr[2] = { (uint8_t)(qlen >> 8), (uint8_t)(qlen & 0xFF) };
    if (!write_all(c, hdr, sizeof(hdr)) || !write_all(c, query, qlen)) {
        dot_disconnect(c);
        return -1;
    }

    if (!read_all(c, hdr, sizeof(hdr))) {
        dot_disconnect(c);
        return -1;
    }
    size_t rlen = ((size_t)hdr[0] << 8) | hdr[1];
    if (rlen == 0) {
        /* A zero-length response is not valid DNS; treat it as a broken
         * connection rather than returning an empty reply. */
        dot_disconnect(c);
        return -1;
    }
    if (rlen > cap) {
        ESP_LOGW(TAG, "response of %u bytes exceeds the %u-byte buffer",
                 (unsigned)rlen, (unsigned)cap);
        dot_disconnect(c);   /* cannot resynchronise mid-stream */
        return -1;
    }
    if (!read_all(c, out, rlen)) {
        dot_disconnect(c);
        return -1;
    }

    /* Same sanity check the DoH path makes: the reply must echo our ID and be
     * flagged as a response, otherwise we would hand the client nonsense. */
    if (rlen >= 12 && (out[0] != query[0] || out[1] != query[1] || (out[2] & 0x80) == 0)) {
        ESP_LOGW(TAG, "response does not match the query");
        dot_disconnect(c);
        return -1;
    }
    return (int)rlen;
}
