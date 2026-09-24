/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Per-device DNS policy: each client MAC may be pinned to its own resolver and
 * protocol, so one device can use a domestic DoH endpoint while another uses
 * DoT or plain DNS.
 *
 * Rules are keyed by MAC, not by address, because a client's DHCP address can
 * change while the MAC does not. The relay, however, only ever sees the source
 * IP of a query, so a MAC->IP map is maintained alongside the rules and
 * refreshed from DHCP lease events (see dns_rules_note_ip).
 *
 * Lookups happen on the DNS hot path, so the whole view - rules plus the IP map -
 * is double-buffered and published by an index flip, exactly as static_leases
 * does. Readers take no lock and never block.
 *
 * A device with no rule falls through to the default resolver, which is the
 * single global DoH endpoint that existed before this module. That keeps the
 * previous behaviour as the fallback if anything here misbehaves.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define DNS_RULE_MAX      4     /* distinct per-device overrides */
#define DNS_RULE_ADDR_MAX 96

typedef enum {
    DNS_MODE_DOH = 0,   /* address is an https:// URL  */
    DNS_MODE_DOT,       /* address is IP[:port], default 853 */
    DNS_MODE_PLAIN,     /* address is IP[:port], default 53  */
} dns_mode_t;

typedef struct {
    uint8_t mac[6];
    uint8_t mode;                       /* dns_mode_t */
    char    addr[DNS_RULE_ADDR_MAX];
} dns_rule_t;

void dns_rules_init(void);

int dns_rules_list(dns_rule_t *out, int max);

/* Validate and store (or replace) the rule for `mac`, then persist. */
esp_err_t dns_rules_set(const uint8_t mac[6], uint8_t mode, const char *addr);

esp_err_t dns_rules_remove(const uint8_t mac[6]);

/* Feed a client's current address, from a DHCP lease event. Keeps the IP->rule
 * map current so the relay can resolve a query's source address to a rule. */
void dns_rules_note_ip(const uint8_t mac[6], uint32_t ip);

/*
 * Hot path. Copies the rule for the client at `ip` (network byte order) into
 * *out and returns true; false means "no rule, use the default".
 *
 * `slot_out` receives the rule's index. The caller keys its resolver instance
 * on that index rather than on the address, so editing a rule reuses its slot
 * and the number of resolvers a worker can hold stays bounded by the table
 * size - no accumulation of stale entries.
 */
bool dns_rules_lookup_ip(uint32_t ip, dns_rule_t *out, int *slot_out);
