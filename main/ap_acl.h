/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AP client allow-list.
 *
 * IMPORTANT LIMITATION, stated here because it shapes everything below: ESP-IDF
 * has no access-control API for the soft-AP. The only "blacklist" in the whole
 * esp_wifi component is the roaming app's upstream-BSSID list, which is
 * unrelated. So this cannot refuse a client at association time.
 *
 * What it does instead is enforce after the fact: when a station associates, if
 * the list is enabled and its MAC is not on it, the station is deauthenticated.
 * Consequences the user should know:
 *   - the client completes association and the 4-way handshake before being
 *     kicked, so it is briefly on the network and could in principle transmit
 *     in that window;
 *   - it is reactive rather than preventive, so a client that keeps retrying
 *     will keep being kicked and will keep appearing in the client list;
 *   - it is therefore a deterrent, not access control.
 *
 * Enabling an empty list is refused: it would deauthenticate every client,
 * including the one using the panel, and that is a footgun, not a feature.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define AP_ACL_MAX 8

void ap_acl_init(void);

/* Copy the allowed MACs out; returns the count. */
int ap_acl_list(uint8_t (*out)[6], int max);

bool ap_acl_enabled(void);

/* Refuses to enable an empty list. Returns ESP_ERR_INVALID_STATE in that case. */
esp_err_t ap_acl_set_enabled(bool enabled);

esp_err_t ap_acl_add(const uint8_t mac[6]);
esp_err_t ap_acl_remove(const uint8_t mac[6]);

/* Hot path, lock-free. True when the client may stay. */
bool ap_acl_allows(const uint8_t mac[6]);

/* Deauthenticate `mac` if it is not allowed. No-op when the list is disabled.
 * Returns true when the station was kicked. */
bool ap_acl_kick_if_denied(const uint8_t mac[6]);

/* Sweep every associated station and kick the disallowed ones. Used when the
 * list is enabled or edited, and at boot once the AP exists. */
void ap_acl_enforce_all(void);
