/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/ip_addr.h"

#include "ap_dhcp.h"

static const char *TAG = "ap_dhcp";

/* Defined unconditionally: the declaration is unconditional in the header, and
 * the event is harmless (never fired) when the IDF server is in use. */
ESP_EVENT_DEFINE_BASE(AP_DHCP_EVENT);

#if CONFIG_USE_OWN_DHCPS

/* Relative on purpose: the vendored tree should not sit on the public include
 * path, where its header names could shadow IDF's own dhcpserver headers. */
#include "dhcps/vendored_dhcps.h"
#include "dhcps/vendored_dhcps_options.h"   /* SUBNET_MASK, DOMAIN_NAME_SERVER, ... */

static dhcps_t *s_dhcps;

/*
 * Fires after an ACK has been transmitted, i.e. from the UDP send path, so this
 * runs on the lwIP TCPIP thread. It must not block: the client table's mutex is
 * held by the HTTP task around esp_wifi_ap_get_sta_list(), and waiting for it
 * here would stall the entire network stack, forwarding included. IDF's own
 * lease callback has the identical constraint and defers the same way -- post
 * an event and let the event loop task do the bookkeeping.
 *
 * Reading the pool for the hostname is safe on this thread (the pool belongs to
 * it); only handing the result off is deferred.
 */
static void on_new_lease(void *arg, uint8_t client_ip[4], uint8_t client_mac[6])
{
    (void)arg;

    ap_dhcp_lease_t evt = {0};
    memcpy(&evt.ip.addr, client_ip, sizeof(evt.ip.addr));
    memcpy(evt.mac, client_mac, sizeof(evt.mac));
    if (s_dhcps != NULL) {
        dhcps_get_hostname_on_mac(s_dhcps, client_mac, evt.hostname, sizeof(evt.hostname));
    }

    /* Timeout 0: never block the TCPIP thread, even if the queue is full. */
    if (esp_event_post(AP_DHCP_EVENT, AP_DHCP_EV_LEASE, &evt, sizeof(evt), 0) != ESP_OK) {
        ESP_LOGW(TAG, "lease event dropped (queue full)");
    }
}

const char *ap_dhcp_impl(void)
{
    return "own";
}

esp_err_t ap_dhcp_start(esp_netif_t *ap_netif)
{
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(ap_netif, &info) != ESP_OK || info.ip.addr == 0) {
        ESP_LOGE(TAG, "AP has no address yet");
        return ESP_ERR_INVALID_STATE;
    }

    struct netif *n = (struct netif *)esp_netif_get_netif_impl(ap_netif);
    if (n == NULL) {
        ESP_LOGE(TAG, "no lwIP netif behind the AP interface");
        return ESP_ERR_INVALID_STATE;
    }

    s_dhcps = dhcps_new();
    if (s_dhcps == NULL) {
        ESP_LOGE(TAG, "dhcps_new failed");
        return ESP_ERR_NO_MEM;
    }

    /* The subnet mask has to be in place before start: dhcps_start() validates
     * it against the server address and returns ERR_ARG otherwise. */
    ip4_addr_t mask = { .addr = info.netmask.addr };
    dhcps_set_option_info(s_dhcps, SUBNET_MASK, &mask, sizeof(mask));

    /* Point clients at ourselves -- the local DoH relay answers on this address.
     * Both halves are needed: the offer flag decides whether option 6 is
     * emitted at all, and the address is what goes in it. */
    dhcps_offer_t offer_dns = OFFER_DNS;
    dhcps_set_option_info(s_dhcps, DOMAIN_NAME_SERVER, &offer_dns, sizeof(offer_dns));
    ip_addr_t dns = {0};
    /* The _val form assigns by value. The pointer form is a macro expanding to
     * `do { if (ipaddr) ... }`, and passing &dns makes GCC's -Waddress fire
     * ("the address will always evaluate as true") -- fatal under -Werror. */
    ip_addr_set_ip4_u32_val(dns, info.ip.addr);
    dhcps_dns_setserver(s_dhcps, &dns);

    /* dhcps_offer defaults to 0xFF, which already includes OFFER_ROUTER, so the
     * gateway option is emitted using the netif's gateway (192.168.4.1). Set it
     * explicitly so this does not depend on an upstream default. */
    dhcps_offer_t offer_router = OFFER_ROUTER;
    dhcps_set_option_info(s_dhcps, ROUTER_SOLICITATION_ADDRESS, &offer_router,
                          sizeof(offer_router));

    dhcps_set_new_lease_cb(s_dhcps, on_new_lease, NULL);

    /* dhcps_start takes lwIP's ip4_addr_t, not esp_netif's esp_ip4_addr_t;
     * same layout, different type. */
    ip4_addr_t server = { .addr = info.ip.addr };

    if (dhcps_start(s_dhcps, n, server) != ERR_OK) {
        ESP_LOGE(TAG, "dhcps_start failed");
        dhcps_delete(s_dhcps);
        s_dhcps = NULL;
        return ESP_FAIL;
    }

    /* Derive the prefix length rather than assuming /24, so the log cannot
     * misreport the subnet if the AP address is ever changed. */
    int prefix = 0;
    for (uint32_t m = info.netmask.addr; m != 0; m >>= 1) {
        prefix += (int)(m & 1);
    }

    ESP_LOGI(TAG, "own DHCP server on " IPSTR "/%d, gateway and DNS " IPSTR,
             IP2STR(&info.ip), prefix, IP2STR(&info.ip));

    /*
     * Read the settings back out of the running server. The protocol logic is
     * IDF's own unmodified code, so the part worth verifying is this
     * integration: that the options were accepted in the order dhcps_start()
     * expects, that the pool was computed, and that the DNS address really is
     * ours. dhcps_poll_set() only fills the pool in during dhcps_start(), so
     * this has to happen after it.
     */
    char b_start[IP4ADDR_STRLEN_MAX], b_end[IP4ADDR_STRLEN_MAX];
    char b_mask[IP4ADDR_STRLEN_MAX], b_dns[IP4ADDR_STRLEN_MAX];

    dhcps_lease_t *rb_pool = dhcps_option_info(s_dhcps, REQUESTED_IP_ADDRESS, sizeof(dhcps_lease_t));
    dhcps_time_t *rb_lease = dhcps_option_info(s_dhcps, IP_ADDRESS_LEASE_TIME, sizeof(dhcps_time_t));
    dhcps_offer_t *rb_offer_router = dhcps_option_info(s_dhcps, ROUTER_SOLICITATION_ADDRESS, sizeof(dhcps_offer_t));
    dhcps_offer_t *rb_offer_dns = dhcps_option_info(s_dhcps, DOMAIN_NAME_SERVER, sizeof(dhcps_offer_t));
    ip4_addr_t *rb_mask = dhcps_option_info(s_dhcps, SUBNET_MASK, sizeof(ip4_addr_t));

    if (rb_pool != NULL) {
        if (rb_pool->enable) {
            ip4addr_ntoa_r(&rb_pool->start_ip, b_start, sizeof(b_start));
            ip4addr_ntoa_r(&rb_pool->end_ip, b_end, sizeof(b_end));
            ESP_LOGI(TAG, "pool %s - %s", b_start, b_end);
        } else {
            /* dhcps_poll_set() rejects a range that falls outside the server's
             * subnet, contains the server's own address, or spans more than
             * DHCPS_MAX_LEASE (100) addresses -- then hands out the whole subnet. */
            ESP_LOGE(TAG, "address pool rejected; server falls back to the whole subnet");
        }
    }
    if (rb_lease != NULL) {
        if (rb_mask != NULL) {
            ip4addr_ntoa_r(rb_mask, b_mask, sizeof(b_mask));
        }
        ESP_LOGI(TAG, "lease %u s, mask %s, offer router=%d dns=%d",
                 (unsigned)(*rb_lease * DHCPS_LEASE_UNIT), rb_mask ? b_mask : "-",
                 rb_offer_router ? dhcps_router_enabled(*rb_offer_router) : 0,
                 rb_offer_dns ? dhcps_dns_enabled(*rb_offer_dns) : 0);
    }

    ip4_addr_t dns_out = {0};
    if (dhcps_dns_getserver(s_dhcps, &dns_out) == ERR_OK) {
        ip4addr_ntoa_r(&dns_out, b_dns, sizeof(b_dns));
        ESP_LOGI(TAG, "clients will be told DNS is %s", b_dns);
        if (dns_out.addr != info.ip.addr) {
            ESP_LOGE(TAG, "DNS mismatch: clients would bypass the local relay");
        }
    }

    return ESP_OK;
}

#else  /* !CONFIG_USE_OWN_DHCPS */

/*
 * Status quo: IDF's DHCP server runs as part of esp_netif and starts on its own
 * when the AP interface is created. Restart it around the DNS option so clients
 * are pointed at the local relay rather than the upstream resolver.
 */
const char *ap_dhcp_impl(void)
{
    return "idf";
}

esp_err_t ap_dhcp_start(esp_netif_t *ap_netif)
{
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(ap_netif, &info) != ESP_OK || info.ip.addr == 0) {
        ESP_LOGE(TAG, "AP has no address yet");
        return ESP_ERR_INVALID_STATE;
    }

    esp_netif_dns_info_t dns = {0};
    dns.ip.type = ESP_IPADDR_TYPE_V4;
    dns.ip.u_addr.ip4.addr = info.ip.addr;

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(ap_netif));
    uint8_t offer_dns = 0x02; /* DHCPS_OFFER_DNS */
    esp_err_t err_dns = esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns);
    esp_err_t err_opt = esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                                               ESP_NETIF_DOMAIN_NAME_SERVER,
                                               &offer_dns, sizeof(offer_dns));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_start(ap_netif));

    if (err_dns != ESP_OK || err_opt != ESP_OK) {
        ESP_LOGE(TAG, "DNS advertisement failed (%s / %s) -- clients will bypass DoH",
                 esp_err_to_name(err_dns), esp_err_to_name(err_opt));
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "idf DHCP server, clients told to use " IPSTR " as DNS",
             IP2STR(&info.ip));
    return ESP_OK;
}

#endif /* CONFIG_USE_OWN_DHCPS */
