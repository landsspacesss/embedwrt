/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_mac.h"          /* MAC2STR */
#include "nvs.h"
#include "lwip/def.h"         /* ntohl */

#include "static_leases.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY       "leases"

static const char *TAG = "leases";

/*
 * Two buffers plus an index. Readers follow s_active and only ever touch that
 * copy, so they are never blocked and never block. A writer fills the copy that
 * is not active and then flips the index with a single store; a reader either
 * sees the old table or the new one, never a mixture.
 */
static static_lease_t s_tab[2][STATIC_LEASE_MAX];
static int s_count[2];
static volatile int s_active;
static SemaphoreHandle_t s_write_lock;

static void persist(int slot)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open NVS to save leases");
        return;
    }
    if (nvs_set_blob(h, NVS_KEY, s_tab[slot], (size_t)s_count[slot] * sizeof(static_lease_t)) != ESP_OK) {
        ESP_LOGE(TAG, "cannot save leases");
    }
    nvs_commit(h);
    nvs_close(h);
}

void static_leases_init(void)
{
    if (s_write_lock == NULL) {
        s_write_lock = xSemaphoreCreateMutex();
    }

    size_t len = sizeof(s_tab[0]);
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, NVS_KEY, s_tab[0], &len) == ESP_OK && len % sizeof(static_lease_t) == 0) {
            s_count[0] = (int)(len / sizeof(static_lease_t));
        }
        nvs_close(h);
    }
    s_active = 0;
    ESP_LOGI(TAG, "%d static lease(s) loaded", s_count[0]);
}

bool static_leases_lookup(const uint8_t mac[6], uint32_t *ip)
{
    /* Snapshot the index once: a flip mid-iteration must not make us read one
     * buffer's entries against the other's count. */
    int idx = s_active;
    int n = s_count[idx];
    for (int i = 0; i < n; i++) {
        if (memcmp(s_tab[idx][i].mac, mac, 6) == 0) {
            if (ip != NULL) {
                *ip = s_tab[idx][i].ip;
            }
            return true;
        }
    }
    return false;
}

int static_leases_list(static_lease_t *out, int max)
{
    int idx = s_active;
    int n = s_count[idx];
    if (n > max) {
        n = max;
    }
    memcpy(out, s_tab[idx], (size_t)n * sizeof(static_lease_t));
    return n;
}

/* Replace the active table with `next` and persist it. Caller holds the lock. */
static void commit(int next, int next_count)
{
    s_count[next] = next_count;
    s_active = next;            /* single store publishes the new table */
    persist(next);
}

esp_err_t static_leases_add(const uint8_t mac[6], uint32_t ip,
                            uint32_t ap_ip, uint32_t netmask,
                            uint32_t pool_first, uint32_t pool_last)
{
    if (s_write_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Host byte order makes the range comparisons readable. */
    uint32_t ip_h = ntohl(ip);
    uint32_t ap_h = ntohl(ap_ip);
    uint32_t mask_h = ntohl(netmask);
    uint32_t first_h = ntohl(pool_first);
    uint32_t last_h = ntohl(pool_last);

    if (ip == 0 || ip == 0xFFFFFFFFu) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((ip_h & mask_h) != (ap_h & mask_h)) {
        ESP_LOGE(TAG, "lease %08x is outside the AP subnet", ip_h);
        return ESP_ERR_INVALID_ARG;
    }
    if (ip_h == ap_h) {
        ESP_LOGE(TAG, "lease %08x is the AP's own address", ip_h);
        return ESP_ERR_INVALID_ARG;
    }
    if (ip_h == (ap_h & mask_h)) {
        ESP_LOGE(TAG, "lease %08x is the network address", ip_h);
        return ESP_ERR_INVALID_ARG;
    }
    if (ip_h == ((ap_h & mask_h) | ~mask_h)) {
        ESP_LOGE(TAG, "lease %08x is the broadcast address", ip_h);
        return ESP_ERR_INVALID_ARG;
    }
    /* Overlapping the pool is the one conflict that actually breaks things:
     * the allocator could hand the same address to somebody else. */
    if (ip_h >= first_h && ip_h <= last_h) {
        ESP_LOGE(TAG, "lease %08x falls inside the dynamic pool (%08x-%08x)",
                 ip_h, first_h, last_h);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ESP_OK;
    xSemaphoreTake(s_write_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    memcpy(s_tab[next], s_tab[cur], (size_t)s_count[cur] * sizeof(static_lease_t));
    int n = s_count[cur];

    int slot = -1;
    for (int i = 0; i < n; i++) {
        if (memcmp(s_tab[next][i].mac, mac, 6) == 0) {
            slot = i;               /* same MAC: replace in place */
            break;
        }
        if (s_tab[next][i].ip == ip) {
            ESP_LOGE(TAG, "address already leased to another MAC");
            err = ESP_ERR_INVALID_ARG;
            goto out;
        }
    }
    if (slot < 0) {
        if (n >= STATIC_LEASE_MAX) {
            ESP_LOGE(TAG, "lease table full (%d)", STATIC_LEASE_MAX);
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        slot = n++;
    }

    memcpy(s_tab[next][slot].mac, mac, 6);
    s_tab[next][slot].ip = ip;
    commit(next, n);
    ESP_LOGI(TAG, "lease " MACSTR " -> %08x", MAC2STR(mac), ntohl(ip));

out:
    xSemaphoreGive(s_write_lock);
    return err;
}

esp_err_t static_leases_remove(const uint8_t mac[6])
{
    if (s_write_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ESP_ERR_NOT_FOUND;
    xSemaphoreTake(s_write_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    int n = 0;
    for (int i = 0; i < s_count[cur]; i++) {
        if (memcmp(s_tab[cur][i].mac, mac, 6) == 0) {
            err = ESP_OK;
            continue;               /* drop it */
        }
        s_tab[next][n++] = s_tab[cur][i];
    }
    if (err == ESP_OK) {
        commit(next, n);
        ESP_LOGI(TAG, "lease for " MACSTR " removed", MAC2STR(mac));
    }

    xSemaphoreGive(s_write_lock);
    return err;
}
