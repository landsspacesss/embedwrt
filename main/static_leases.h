/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Static DHCP leases: MAC -> fixed IPv4 address.
 *
 * The vendored DHCP server calls static_leases_lookup() from inside parse_msg(),
 * which runs on the lwIP TCPIP thread. Blocking that thread stalls packet
 * forwarding for every client, so the lookup is lock-free: the table is
 * double-buffered, writers build into the inactive copy and then flip an index.
 * Readers never take a lock and never allocate.
 *
 * Addresses must sit outside the dynamic pool. The pool is 192.168.4.2-101
 * (dhcps_poll_set caps it at DHCPS_MAX_LEASE=100 and skips the server's own
 * address), so .102-.254 are free for leases and the allocator can never hand
 * one out by accident. Ranges are validated on add, with the pool bounds
 * supplied by the caller so this module does not have to know them.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define STATIC_LEASE_MAX 16

typedef struct {
    uint8_t mac[6];
    uint32_t ip;        /* network byte order, as in esp_ip4_addr_t.addr */
} static_lease_t;

void static_leases_init(void);

/* Lock-free. Returns true and fills *ip (network byte order) on a match. */
bool static_leases_lookup(const uint8_t mac[6], uint32_t *ip);

/* Copy the whole table out. Returns the number of entries written. */
int static_leases_list(static_lease_t *out, int max);

/* `ip` network byte order. Rejects addresses outside [net, broadcast) of the AP
 * subnet, the AP's own address, and anything inside [pool_first, pool_last]. */
esp_err_t static_leases_add(const uint8_t mac[6], uint32_t ip,
                            uint32_t ap_ip, uint32_t netmask,
                            uint32_t pool_first, uint32_t pool_last);

esp_err_t static_leases_remove(const uint8_t mac[6]);
