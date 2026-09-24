/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * DNS relay for the AP side of the repeater.
 *
 * Listens on UDP :53 for client queries. Because RFC 8484 (DoH) POSTs the DNS
 * wire-format message verbatim, the relay never has to parse a DNS body on the
 * fast path: it forwards the client's bytes to the DoH resolver and sends the
 * response bytes straight back. That preserves the transaction ID, the question
 * section, CNAME chains, TTLs and every record type for free.
 *
 * Parsing is only used as a best-effort cache key. If it fails the query is
 * still relayed, just not cached.
 *
 * Resolution order per query: cache -> DoH -> plaintext upstream -> SERVFAIL.
 * DoH is only attempted once the system clock is valid, since certificate
 * expiry validation needs a real time source, and is skipped for a cooldown
 * period after repeated failures so a dead resolver does not add its connect
 * timeout to every single lookup.
 */
#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "esp_netif.h"

/* Not all DoH resolvers are reachable from every network -- operate only ones
 * answer inside mainland China, for instance. The endpoint is therefore
 * user-configurable and persisted in NVS.
 *
 * Default to Tencent's over Alibaba's for a concrete reason: a full handshake
 * costs ~2 s here, so session resumption matters. 1.12.12.12 negotiates TLS 1.2
 * and issues an in-handshake ticket (300 s lifetime) that resumes cleanly,
 * whereas 223.5.5.5 only hands out TLS 1.3 post-handshake tickets, which cannot
 * be reused while this firmware has TLS 1.3 disabled. */
#define DOH_URL_MAX        128
#define DOH_DEFAULT_URL    "https://1.12.12.12/dns-query"

/* Start the UDP :53 listener and its worker pool. `doh_url` may be NULL, in
 * which case DOH_DEFAULT_URL is used. */
esp_err_t doh_relay_start(esp_netif_t *ap_netif, esp_netif_t *sta_netif,
                          const char *doh_url);

/* DoH requires a valid clock for cert validation; call this from the SNTP callback. */
void doh_relay_set_time_synced(bool synced);

/* Point the relay at a different resolver. Only https:// URLs are accepted;
 * returns ESP_ERR_INVALID_ARG otherwise. Live worker sessions are recycled. */
esp_err_t doh_relay_set_url(const char *url);

/* Copy the resolver currently in use into `out`. */
void doh_relay_get_url(char *out, size_t cap);

/* Drop all cached answers, e.g. after the upstream network changed. */
void doh_relay_flush_cache(void);

/* "off" | "doh" | "fallback (...)" -- for the web UI status line. */
const char *doh_relay_mode(void);

/* Counters for diagnosing throughput drops: a full TLS handshake costs ~2 s of
 * software ECC on this chip, so correlating new connections with a stalled
 * forwarding path tells us whether the CPU is the cause. */
typedef struct {
    uint32_t queries;
    uint32_t cached;
    uint32_t new_conns;   /* full TLS handshakes performed */
    uint32_t pooled;      /* queries served over a reused connection */
    uint32_t fallback;    /* answered in plaintext */
    uint32_t servfail;
    uint32_t drops;       /* requests our own queue could not accept */
} doh_stats_t;

void doh_relay_get_stats(doh_stats_t *out);
