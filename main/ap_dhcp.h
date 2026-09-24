/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Owns the AP's DHCP server.
 *
 * Two implementations exist and exactly one is compiled, chosen by
 * CONFIG_USE_OWN_DHCPS:
 *
 *   - the status quo: ESP-IDF's server, driven through esp_netif
 *   - a vendored copy of that same server, which we can extend (static leases)
 *
 * They cannot coexist: both define dhcps_new/dhcps_start/... so enabling both
 * would be a duplicate-symbol error at link time. CONFIG_USE_OWN_DHCPS requires
 * CONFIG_LWIP_DHCPS=n, and switching it off is the one-step rollback.
 */
#pragma once

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"

/*
 * Lease notifications.
 *
 * A dedicated event base rather than IP_EVENT_ASSIGNED_IP_TO_CLIENT, because
 * that struct sizes its hostname field from
 * CONFIG_LWIP_DHCPS_MAX_HOSTNAME_LEN -- which the IDF Kconfig deletes when
 * LWIP_DHCPS=n, collapsing the field to a single NUL and making a client's
 * hostname impossible to carry.
 *
 * The event exists so the DHCP callback never does the work itself: it runs in
 * the lwIP TCPIP thread, where taking the client table's mutex could stall the
 * whole stack. See the handler in my_wifi_router.c.
 */
ESP_EVENT_DECLARE_BASE(AP_DHCP_EVENT);

typedef enum {
    AP_DHCP_EV_LEASE = 0,   /* a client has been given an address */
} ap_dhcp_event_id_t;

typedef struct {
    esp_ip4_addr_t ip;
    uint8_t mac[6];
    char hostname[64];
} ap_dhcp_lease_t;

/* Configure and start the DHCP server on the AP interface. Safe to call once,
 * after esp_wifi_start() and after the AP has its address. */
esp_err_t ap_dhcp_start(esp_netif_t *ap_netif);

/* Which implementation is compiled in: "own" or "idf". For /status. */
const char *ap_dhcp_impl(void);
