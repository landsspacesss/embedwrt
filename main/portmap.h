/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Port forwarding: expose a service on a client behind the AP at a port on the
 * repeater's upstream (station) address.
 *
 *   client on 192.168.0.x  ->  STA_IP:mport  =>  forwarded to  daddr:dport
 *                              (a client on 192.168.4.x)
 *
 * NAT is one-way by construction: clients behind the AP can reach out, but
 * nothing upstream can reach in. A mapping opens exactly one hole.
 *
 * Limitation worth stating plainly: the external address is the repeater's
 * *station* address, which is itself behind the upstream router's NAT. So a
 * mapping is reachable from the upstream LAN, not from the internet, unless a
 * second forward is added on that router. No firmware change can avoid this --
 * it is a consequence of the repeater being a NAT client itself.
 *
 * The mappings are applied from the TCPIP thread via esp_netif_tcpip_exec()
 * because ip_portmap_add() mutates a table the stack reads while forwarding.
 */
#pragma once

#include <stdint.h>

#include "esp_err.h"

#define PORTMAP_MAX 16   /* comfortably under lwIP's IP_PORTMAP_MAX (32) */

typedef struct {
    uint8_t  proto;    /* IPPROTO_TCP or IPPROTO_UDP */
    uint16_t mport;    /* external port, host order */
    uint32_t daddr;    /* internal IPv4, network order */
    uint16_t dport;    /* internal port, host order */
} portmap_entry_t;

void portmap_init(void);

int portmap_list(portmap_entry_t *out, int max);

/* Validates, persists, and pushes to lwIP. `ap_ip`/`netmask` are the AP's
 * address and mask, used to check the target is actually on the AP's subnet. */
esp_err_t portmap_add(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport,
                      uint32_t ap_ip, uint32_t netmask);

esp_err_t portmap_remove(uint8_t proto, uint16_t mport);

/*
 * Re-push every mapping using `sta_ip` as the external address.
 *
 * Must be called on every station IP change: ip_portmap_add() stores the
 * external address given at call time, so a mapping created before a new DHCP
 * lease would keep rewriting replies to the old address and the forwarded
 * connection would break. The table itself survives NAPT being re-enabled,
 * because ip_napt_init() is a no-op once the tables exist.
 */
esp_err_t portmap_apply_all(uint32_t sta_ip);
