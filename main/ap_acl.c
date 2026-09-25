/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "nvs.h"

#include "ap_acl.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY       "acl"

static const char *TAG = "ap_acl";

/* `enabled` travels with the list, in one double-buffered view, so a reader can
 * never see "enabled" paired with a list from a different edit. */
typedef struct {
    bool    enabled;
    int     count;
    uint8_t macs[AP_ACL_MAX][6];
} acl_view_t;

static acl_view_t s_view[2];
static volatile int s_active;
static SemaphoreHandle_t s_lock;

static void persist(int slot)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open NVS");
        return;
    }
    nvs_set_blob(h, NVS_KEY, &s_view[slot], sizeof(acl_view_t));
    nvs_commit(h);
    nvs_close(h);
}

void ap_acl_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    size_t len = sizeof(s_view[0]);
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, NVS_KEY, &s_view[0], &len) == ESP_OK &&
                len == sizeof(acl_view_t) &&
                s_view[0].count >= 0 && s_view[0].count <= AP_ACL_MAX) {
            /* fall through with what was stored */
        } else {
            memset(&s_view[0], 0, sizeof(s_view[0]));
        }
        nvs_close(h);
    }
    s_active = 0;
    ESP_LOGI(TAG, "allow-list %s, %d MAC(s)",
             s_view[0].enabled ? "ENABLED" : "disabled", s_view[0].count);
}

/* Caller holds the lock. */
static void publish(int next)
{
    persist(next);
    s_active = next;   /* single store publishes the whole view */
}

int ap_acl_list(uint8_t (*out)[6], int max)
{
    int slot = s_active;
    int n = s_view[slot].count;
    if (out == NULL || max <= 0) {
        return 0;
    }
    if (n > max) {
        n = max;
    }
    memcpy(out, s_view[slot].macs, (size_t)n * 6);
    return n;
}

bool ap_acl_enabled(void)
{
    return s_view[s_active].enabled;
}

bool ap_acl_allows(const uint8_t mac[6])
{
    int slot = s_active;
    if (!s_view[slot].enabled) {
        return true;   /* no list in force */
    }
    for (int i = 0; i < s_view[slot].count; i++) {
        if (memcmp(s_view[slot].macs[i], mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

esp_err_t ap_acl_set_enabled(bool enabled)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    if (enabled && s_view[cur].count == 0) {
        /* Would deauthenticate every client including the one driving the panel. */
        xSemaphoreGive(s_lock);
        ESP_LOGE(TAG, "refusing to enable an empty allow-list: it would kick every client");
        return ESP_ERR_INVALID_STATE;
    }
    if (s_view[cur].enabled == enabled) {
        xSemaphoreGive(s_lock);
        return ESP_OK;
    }

    int next = 1 - cur;
    s_view[next] = s_view[cur];
    s_view[next].enabled = enabled;
    publish(next);
    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "allow-list %s", enabled ? "ENABLED" : "disabled");
    return ESP_OK;
}

esp_err_t ap_acl_add(const uint8_t mac[6])
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    for (int i = 0; i < s_view[cur].count; i++) {
        if (memcmp(s_view[cur].macs[i], mac, 6) == 0) {
            xSemaphoreGive(s_lock);
            return ESP_OK;   /* already present */
        }
    }
    if (s_view[cur].count >= AP_ACL_MAX) {
        xSemaphoreGive(s_lock);
        ESP_LOGE(TAG, "allow-list full (%d)", AP_ACL_MAX);
        return ESP_ERR_NO_MEM;
    }

    int next = 1 - cur;
    s_view[next] = s_view[cur];
    memcpy(s_view[next].macs[s_view[next].count], mac, 6);
    s_view[next].count++;
    publish(next);
    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "allow-list += " MACSTR, MAC2STR(mac));
    return ESP_OK;
}

esp_err_t ap_acl_remove(const uint8_t mac[6])
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int cur = s_active;
    int next = 1 - cur;
    s_view[next] = s_view[cur];
    int n = 0;
    bool found = false;
    for (int i = 0; i < s_view[cur].count; i++) {
        if (memcmp(s_view[cur].macs[i], mac, 6) == 0) {
            found = true;
            continue;
        }
        memcpy(s_view[next].macs[n++], s_view[cur].macs[i], 6);
    }
    if (!found) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_NOT_FOUND;
    }
    s_view[next].count = n;
    /* Removing the last entry must not leave an enabled empty list behind: that
     * state would kick everyone, and set_enabled() refuses to create it. */
    if (n == 0) {
        s_view[next].enabled = false;
        ESP_LOGW(TAG, "allow-list emptied, so it has been disabled");
    }
    publish(next);
    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "allow-list -= " MACSTR, MAC2STR(mac));
    return ESP_OK;
}

bool ap_acl_kick_if_denied(const uint8_t mac[6])
{
    if (ap_acl_allows(mac)) {
        return false;
    }

    uint16_t aid = 0;
    if (esp_wifi_ap_get_sta_aid(mac, &aid) != ESP_OK || aid == 0) {
        /* Already gone, or the aid is unknown. Never call with aid 0: that
         * deauthenticates every station. */
        ESP_LOGW(TAG, "denied " MACSTR " but no aid; leaving it alone", MAC2STR(mac));
        return false;
    }
    esp_err_t err = esp_wifi_deauth_sta(aid);
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "deauthenticated " MACSTR " (aid %u): not on the allow-list",
                 MAC2STR(mac), aid);
        return true;
    }
    ESP_LOGE(TAG, "deauth of " MACSTR " failed: %s", MAC2STR(mac), esp_err_to_name(err));
    return false;
}

void ap_acl_enforce_all(void)
{
    if (!ap_acl_enabled()) {
        return;
    }
    wifi_sta_list_t list;
    memset(&list, 0, sizeof(list));
    if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) {
        return;
    }
    int kicked = 0;
    for (int i = 0; i < list.num; i++) {
        if (ap_acl_kick_if_denied(list.sta[i].mac)) {
            kicked++;
        }
    }
    ESP_LOGI(TAG, "swept %d associated station(s), kicked %d", list.num, kicked);
}
