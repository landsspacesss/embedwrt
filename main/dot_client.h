/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal DNS-over-TLS client (RFC 7858) built on esp_tls.
 *
 * DoT is just DNS-over-TCP behind TLS: each message is preceded by a 2-byte
 * big-endian length. That makes it markedly simpler than the DoH path - no
 * HTTP, no base64, no content-type juggling - and it preserves the query bytes
 * verbatim just the same, so transaction IDs and every record type survive.
 *
 * Connection state is kept across calls so the TLS session is reused; a full
 * handshake on this chip costs seconds (see the sdkconfig notes), so paying it
 * per query would be unusable. Session tickets are carried over explicitly:
 * esp_tls exposes no "close but keep the session" call, so the ticket is
 * retrieved with esp_tls_get_client_session() before the connection is
 * destroyed and handed back via cfg.client_session on the next connect.
 *
 * Addresses must be IPv4 literals. A hostname would have to be resolved before
 * it could resolve anything, so parsing rejects one up front - and servers that
 * serve DoT by IP, such as 223.5.5.5, carry an IP SAN in their certificate, so
 * normal verification still applies and skip_common_name is left off.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct dot_conn dot_conn_t;

/* Parse "IP" or "IP:port" (default port 853). Returns NULL if malformed.
 * Does not connect; connection is deferred to the first dot_exchange(). */
dot_conn_t *dot_open(const char *host_port);

/* One query/response exchange. Connects if not already connected. Returns the
 * response length, or -1 on failure, in which case the caller may call again
 * once to retry on a fresh connection. */
int dot_exchange(dot_conn_t *c, const uint8_t *query, size_t qlen,
                 uint8_t *out, size_t cap);

/* Drop the connection but keep the parsed address and the saved session, so a
 * later dot_exchange() reconnects. */
void dot_disconnect(dot_conn_t *c);

/* Release everything, including the saved session. */
void dot_free(dot_conn_t *c);

/* For diagnostics: whether a connection is currently established. */
bool dot_is_connected(const dot_conn_t *c);
