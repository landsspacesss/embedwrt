/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Per-device attributes: whether a client is an IoT device, and which client
 * owns it.
 *
 * This is what gives a guest anything to see. A visitor cannot log in, so the
 * only identity available to it is the source address of its HTTP request,
 * resolved to a MAC. "My devices" therefore means: the device whose MAC that is,
 * plus every device flagged as IoT and owned by that same MAC.
 *
 * A record exists only for a device that has been flagged or owned. Absence
 * means "not an IoT device, no owner", which is the state of every device until
 * an administrator says otherwise - so nothing changes for existing setups.
 *
 * Ownership is keyed on MAC rather than address because a client's DHCP address
 * moves while its MAC does not. The consequence to be aware of: iOS generates a
 * new random MAC when its remembered network changes (a different SSID, or
 * "Forget This Network"), and the devices it owned then become unowned. That is
 * why ownership is reassignable from the panel rather than fixed at the moment
 * of tagging.
 *
 * Read from the request path, so the table is double-buffered and published by
 * an index flip: readers take no lock. Same pattern as static_leases and
 * dns_rules.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#define DEVICES_MAX 16

typedef struct {
    uint8_t mac[6];
    bool    iot;
    uint8_t owner[6];   /* all-zero when unowned */
} device_rec_t;

void devices_init(void);

/* Number of records for a MAC, or -1. */
int devices_records(device_rec_t *out, int max);

/* Look one up. Returns false when the MAC has no record. */
bool devices_get(const uint8_t mac[6], device_rec_t *out);

/*
 * Set both attributes at once. `owner` NULL clears ownership. Setting neither
 * flag nor owner drops the record entirely, so the table does not accumulate
 * entries for devices that were merely un-flagged.
 *
 * For changing one without risking the other, prefer devices_set_iot() - passing
 * a NULL owner here clears it, which is a silent loss of user-visible state if
 * the caller only meant to toggle the flag.
 */
esp_err_t devices_set(const uint8_t mac[6], bool iot, const uint8_t *owner);

/* Toggle the IoT flag, leaving ownership exactly as it is. */
esp_err_t devices_set_iot(const uint8_t mac[6], bool iot);

/* Set (owner != NULL) or clear (owner == NULL) ownership, leaving the flag. */
esp_err_t devices_set_owner(const uint8_t mac[6], const uint8_t *owner);

/*
 * May `viewer` see and configure `target`?
 *
 * True when they are the same device, or when `target` is an IoT device owned by
 * `viewer`. Administrators do not go through this at all.
 */
bool devices_visible(const uint8_t target[6], const uint8_t viewer[6]);

/* MAC comparison that treats an all-zero MAC as "nobody". */
bool devices_mac_is_set(const uint8_t mac[6]);
