/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"

#include "clients.h"

static const char *TAG = "clients";

static client_info_t s_clients[CLIENTS_MAX];
static SemaphoreHandle_t s_lock;

void clients_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
}

static client_info_t *find_locked(const uint8_t mac[6])
{
    for (int i = 0; i < CLIENTS_MAX; i++) {
        if (s_clients[i].used && memcmp(s_clients[i].mac, mac, 6) == 0) {
            return &s_clients[i];
        }
    }
    return NULL;
}

static client_info_t *claim_locked(const uint8_t mac[6])
{
    client_info_t *e = find_locked(mac);
    if (e != NULL) {
        return e;
    }
    for (int i = 0; i < CLIENTS_MAX; i++) {
        if (!s_clients[i].used) {
            e = &s_clients[i];
            memset(e, 0, sizeof(*e));
            memcpy(e->mac, mac, 6);
            e->used = true;
            e->joined_us = esp_timer_get_time();
            return e;
        }
    }
    return NULL;
}

void clients_note_join(const uint8_t mac[6])
{
    if (s_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_info_t *e = claim_locked(mac);
    if (e != NULL) {
        /* Re-association restarts the clock. */
        e->joined_us = esp_timer_get_time();
    } else {
        ESP_LOGW(TAG, "no free slot for a newly joined station");
    }
    xSemaphoreGive(s_lock);
}

void clients_note_leave(const uint8_t mac[6])
{
    if (s_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_info_t *e = find_locked(mac);
    if (e != NULL) {
        e->used = false;
    }
    xSemaphoreGive(s_lock);
}

void clients_note_ip(const uint8_t mac[6], esp_ip4_addr_t ip, const char *hostname)
{
    if (s_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_info_t *e = claim_locked(mac);
    if (e != NULL) {
        e->ip = ip;
        e->ip_valid = true;
        if (hostname != NULL && hostname[0] != '\0') {
            snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
        }
    }
    xSemaphoreGive(s_lock);
}

/*
 * The driver is the authority on who is associated, so the snapshot is driven
 * from esp_wifi_ap_get_sta_list() rather than from our own table: that way a
 * missed join/leave event cannot leave a ghost entry behind. Our table only
 * contributes the data the driver does not report - IP, hostname, join time.
 */
int clients_snapshot(client_info_t *out, int max)
{
    if (out == NULL || max <= 0) {
        return 0;
    }

    wifi_sta_list_t sta_list;
    memset(&sta_list, 0, sizeof(sta_list));
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) {
        return 0;
    }

    int n = 0;
    client_info_t *matched[CLIENTS_MAX] = {0};

    if (s_lock != NULL) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    for (int i = 0; i < sta_list.num && n < max; i++) {
        const wifi_sta_info_t *si = &sta_list.sta[i];
        client_info_t *e = find_locked(si->mac);

        client_info_t *dst = &out[n];
        memset(dst, 0, sizeof(*dst));
        memcpy(dst->mac, si->mac, 6);
        dst->rssi = si->rssi;
        dst->phy = si->phy_11ax ? 6 : (si->phy_11n ? 4 : (si->phy_11g ? 2 : 1));

        if (e != NULL) {
            dst->ip = e->ip;
            dst->ip_valid = e->ip_valid;
            memcpy(dst->hostname, e->hostname, sizeof(dst->hostname));
            dst->joined_us = e->joined_us;
            matched[n] = e;   /* remember, so the sweep below spares it */
        }
        n++;
    }

    /* A missed leave event must not leave a ghost entry. Anything in our table
     * that the driver is not currently reporting is stale. */
    for (int i = 0; i < CLIENTS_MAX; i++) {
        if (!s_clients[i].used) {
            continue;
        }
        bool live = false;
        for (int m = 0; m < n; m++) {
            if (matched[m] == &s_clients[i]) {
                live = true;
                break;
            }
        }
        if (!live) {
            s_clients[i].used = false;
        }
    }
    if (s_lock != NULL) {
        xSemaphoreGive(s_lock);
    }
    return n;
}
