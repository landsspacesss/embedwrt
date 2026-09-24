/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Tracks the stations associated with our soft-AP.
 *
 * Per-client byte counters are deliberately absent: esp_wifi exposes no
 * per-station traffic counters, and the NAPT table only tracks TCP sequence
 * numbers, not volumes. The only way to attribute bytes per client would be
 * promiscuous-mode capture, which pushes every frame through the CPU - ruinous
 * on a repeater whose forwarding path is already the bottleneck.
 *
 * What is available, and what matters most for diagnosing a weak client, is the
 * AP-side RSSI: the /status endpoint only ever reported the STA-side link
 * (ESP32 -> upstream), so a client struggling to reach the AP was invisible.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#define CLIENTS_MAX 8   /* AP_MAX_CONN is 7, plus slack */

typedef struct {
    bool used;
    uint8_t mac[6];
    bool ip_valid;
    esp_ip4_addr_t ip;
    char hostname[33];   /* from the DHCP event; empty if the client sent none */
    int64_t joined_us;   /* esp_timer uptime at association */
    int rssi;            /* AP-side, refreshed on read; 0 when unknown */
    uint8_t phy;         /* 1=11b 2=11g 4=11n 5=11a/ac 6=11ax */
} client_info_t;

void clients_init(void);

/* Event hooks. Safe to call before clients_init(); they become no-ops. */
void clients_note_join(const uint8_t mac[6]);
void clients_note_leave(const uint8_t mac[6]);
void clients_note_ip(const uint8_t mac[6], esp_ip4_addr_t ip, const char *hostname);

/* Copy up to `max` associated clients into `out`, refreshing RSSI. Returns the
 * number written. */
int clients_snapshot(client_info_t *out, int max);
