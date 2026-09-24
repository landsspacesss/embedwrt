/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "nvs.h"

#include "dns_rules.h"
#include "clients.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY       "dnsrules"

static const char *TAG = "dns_rules";

/*
 * One view holds the rules and the IP map together, so a reader resolving an IP
 * to a rule always sees a consistent pairing: flipping the index swaps both at
 * once. Two views, published by a single store.
 */
typedef struct {
    dns_rule_t rules[DNS_RULE_MAX];
    int count;
    struct {
        uint32_t ip;
        int8_t   rule;      /* index into rules, -1 if the client has none */
    } map[CLIENTS_MAX];
    int map_count;
} rules_view_t;

static rules_view_t s_view[2];
static volatile int s_active;
static SemaphoreHandle_t s_lock;

static void rebuild_map(int slot)
{
    /* Recomputed from the client table rather than carried over: it is the
     * authority on who currently holds which address. */
    int n = 0;
    static client_info_t snap[CLIENTS_MAX];
    int cn = clients_snapshot(snap, CLIENTS_MAX);

    for (int i = 0; i < cn && n < CLIENTS_MAX; i++) {
        if (!snap[i].ip_valid) {
            continue;
        }
        int idx = -1;
        for (int r = 0; r < s_view[slot].count; r++) {
            if (memcmp(s_view[slot].rules[r].mac, snap[i].mac, 6) == 0) {
                idx = r;
                break;
            }
        }
        s_view[slot].map[n].ip = snap[i].ip.addr;
        s_view[slot].map[n].rule = (int8_t)idx;
        n++;
    }
    s_view[slot].map_count = n;
}

static void persist(int slot)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open NVS");
        return;
    }
    nvs_set_blob(h, NVS_KEY, s_view[slot].rules,
                 (size_t)s_view[slot].count * sizeof(dns_rule_t));
    nvs_commit(h);
    nvs_close(h);
}

void dns_rules_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    size_t len = sizeof(s_view[0].rules);
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, NVS_KEY, s_view[0].rules, &len) == ESP_OK &&
                len % sizeof(dns_rule_t) == 0 &&
                len / sizeof(dns_rule_t) <= DNS_RULE_MAX) {
            s_view[0].count = (int)(len / sizeof(dns_rule_t));
        }
        nvs_close(h);
    }
    s_active = 0;
    ESP_LOGI(TAG, "%d per-device rule(s) loaded", s_view[0].count);
}

/* Reject anything the resolver layer could not act on. Catching it here means
 * the web UI can report a precise reason instead of a resolver failing later. */
static esp_err_t validate(uint8_t mode, const char *addr)
{
    size_t len = strlen(addr);
    if (len == 0 || len >= DNS_RULE_ADDR_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    if (mode == DNS_MODE_DOH) {
        /* Must be https: a plaintext http:// resolver would defeat the point of
         * the option, and the underlying client requires a scheme anyway. */
        if (strncasecmp(addr, "https://", 8) != 0) {
            ESP_LOGE(TAG, "DoH address must be an https:// URL");
            return ESP_ERR_INVALID_ARG;
        }
        return ESP_OK;
    }

    if (mode != DNS_MODE_DOT && mode != DNS_MODE_PLAIN) {
        return ESP_ERR_INVALID_ARG;
    }

    /* DoT and plain DNS take IP[:port]. A hostname would have to be resolved
     * before it could be used to resolve anything, so require a literal. */
    char host[DNS_RULE_ADDR_MAX];
    snprintf(host, sizeof(host), "%s", addr);
    char *colon = strrchr(host, ':');
    long port = (mode == DNS_MODE_DOT) ? 853 : 53;
    if (colon != NULL) {
        *colon = '\0';
        port = strtol(colon + 1, NULL, 10);
    }
    if (port < 1 || port > 65535) {
        ESP_LOGE(TAG, "port must be 1-65535");
        return ESP_ERR_INVALID_ARG;
    }
    unsigned a, b, c, d;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
        ESP_LOGE(TAG, "'%s' must be an IPv4 literal (optionally IP:port)", addr);
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

int dns_rules_list(dns_rule_t *out, int max)
{
    if (out == NULL || max <= 0) {
        return 0;
    }
    int slot = s_active;
    int n = s_view[slot].count;
    if (n > max) {
        n = max;
    }
    memcpy(out, s_view[slot].rules, (size_t)n * sizeof(dns_rule_t));
    return n;
}

esp_err_t dns_rules_set(const uint8_t mac[6], uint8_t mode, const char *addr)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = validate(mode, addr);
    if (err != ESP_OK) {
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    memcpy(s_view[next].rules, s_view[cur].rules,
           (size_t)s_view[cur].count * sizeof(dns_rule_t));
    s_view[next].count = s_view[cur].count;

    int slot = -1;
    for (int i = 0; i < s_view[next].count; i++) {
        if (memcmp(s_view[next].rules[i].mac, mac, 6) == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (s_view[next].count >= DNS_RULE_MAX) {
            ESP_LOGE(TAG, "rule table full (%d)", DNS_RULE_MAX);
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        slot = s_view[next].count++;
    }

    memcpy(s_view[next].rules[slot].mac, mac, 6);
    s_view[next].rules[slot].mode = mode;
    snprintf(s_view[next].rules[slot].addr, DNS_RULE_ADDR_MAX, "%s", addr);

    rebuild_map(next);
    persist(next);
    s_active = next;
    ESP_LOGI(TAG, "rule " MACSTR " -> mode %u, %s", MAC2STR(mac), mode, addr);

out:
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t dns_rules_remove(const uint8_t mac[6])
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = ESP_ERR_NOT_FOUND;

    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    int n = 0;
    for (int i = 0; i < s_view[cur].count; i++) {
        if (memcmp(s_view[cur].rules[i].mac, mac, 6) == 0) {
            err = ESP_OK;
            continue;
        }
        s_view[next].rules[n++] = s_view[cur].rules[i];
    }
    if (err == ESP_OK) {
        s_view[next].count = n;
        rebuild_map(next);
        persist(next);
        s_active = next;
        ESP_LOGI(TAG, "rule for " MACSTR " removed", MAC2STR(mac));
    }

    xSemaphoreGive(s_lock);
    return err;
}

void dns_rules_note_ip(const uint8_t mac[6], uint32_t ip)
{
    if (s_lock == NULL || ip == 0) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    memcpy(s_view[next].rules, s_view[cur].rules, sizeof(s_view[next].rules));
    s_view[next].count = s_view[cur].count;
    rebuild_map(next);
    s_active = next;

    xSemaphoreGive(s_lock);
}

bool dns_rules_lookup_ip(uint32_t ip, dns_rule_t *out, int *slot_out)
{
    int slot = s_active;
    for (int i = 0; i < s_view[slot].map_count; i++) {
        if (s_view[slot].map[i].ip != ip) {
            continue;
        }
        int r = s_view[slot].map[i].rule;
        if (r < 0 || r >= s_view[slot].count) {
            return false;   /* known client, but it has no rule */
        }
        if (out != NULL) {
            *out = s_view[slot].rules[r];
        }
        if (slot_out != NULL) {
            *slot_out = r;
        }
        return true;
    }
    return false;
}
