/* SPDX-License-Identifier: Apache-2.0
 *
 * Local configuration for the vendored DHCP server.
 *
 * Every CONFIG_LWIP_DHCPS_* symbol below carries `depends on LWIP_DHCPS` in the
 * IDF Kconfig, so they all vanish when CONFIG_LWIP_DHCPS=n -- which is exactly
 * the configuration this copy runs in. Supply the same defaults IDF used so the
 * vendored behaviour matches the upstream one.
 */
#pragma once

#include "sdkconfig.h"

#ifndef CONFIG_LWIP_DHCPS_MAX_STATION_NUM
#define CONFIG_LWIP_DHCPS_MAX_STATION_NUM 8      /* IDF default */
#endif

#ifndef CONFIG_LWIP_DHCPS_LEASE_UNIT
#define CONFIG_LWIP_DHCPS_LEASE_UNIT 60          /* IDF default, seconds */
#endif

/* Keep hostnames: clients.c shows them in the client list, and the DHCP server
 * is the only source for them. */
#ifndef CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME
#define CONFIG_LWIP_DHCPS_REPORT_CLIENT_HOSTNAME 1
#endif

#ifndef CONFIG_LWIP_DHCPS_MAX_HOSTNAME_LEN
#define CONFIG_LWIP_DHCPS_MAX_HOSTNAME_LEN 64    /* IDF default */
#endif

/* Replaces the upstream `#if CONFIG_LWIP_DHCPS` gate. That condition is false
 * in our build (we disabled the IDF server), but this file only exists in the
 * build when we are running it ourselves, so the equivalent is unconditionally
 * true. Leaving the original symbol there would silently compile away the
 * per-client hostname storage. */
#define VENDORED_DHCPS 1
