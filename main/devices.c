/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "nvs.h"

#include "devices.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY       "devices"

static const char *TAG = "devices";

typedef struct {
    int count;
    device_rec_t rec[DEVICES_MAX];
} devices_view_t;

static devices_view_t s_view[2];
static volatile int s_active;
static SemaphoreHandle_t s_lock;

/* Separate keys rather than fields in the records blob: growing that struct would
 * fail the size check on load and silently wipe every record. */
#define NVS_KEY_CLAIM  "guestclaim"
#define NVS_KEY_CLRVIS "iotclrvis"
static bool s_guest_claim = true;
static bool s_clear_on_visit = true;

bool devices_mac_is_set(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    return mac != NULL && memcmp(mac, zero, 6) != 0;
}

static void persist(int slot)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open NVS");
        return;
    }
    nvs_set_blob(h, NVS_KEY, &s_view[slot], sizeof(devices_view_t));
    nvs_commit(h);
    nvs_close(h);
}

void devices_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    size_t len = sizeof(s_view[0]);
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, NVS_KEY, &s_view[0], &len) == ESP_OK &&
                len == sizeof(devices_view_t) &&
                s_view[0].count >= 0 && s_view[0].count <= DEVICES_MAX) {
            /* loaded */
        } else {
            memset(&s_view[0], 0, sizeof(s_view[0]));
        }
        nvs_close(h);
    }
    s_active = 0;

    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        uint8_t v = 0;
        if (nvs_get_u8(h, NVS_KEY_CLAIM, &v) == ESP_OK) {
            s_guest_claim = (v != 0);
        }
        if (nvs_get_u8(h, NVS_KEY_CLRVIS, &v) == ESP_OK) {
            s_clear_on_visit = (v != 0);
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "%d device record(s), guest claim %s, clear-on-visit %s",
             s_view[0].count, s_guest_claim ? "on" : "off",
             s_clear_on_visit ? "on" : "off");
}

static esp_err_t save_flag(const char *key, bool on)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_u8(h, key, on ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

bool devices_guest_claim_enabled(void)
{
    return s_guest_claim;
}

esp_err_t devices_set_guest_claim(bool on)
{
    s_guest_claim = on;
    ESP_LOGW(TAG, "guest claiming of unowned IoT devices %s", on ? "ENABLED" : "disabled");
    return save_flag(NVS_KEY_CLAIM, on);
}

bool devices_clear_iot_on_visit(void)
{
    return s_clear_on_visit;
}

esp_err_t devices_set_clear_iot_on_visit(bool on)
{
    s_clear_on_visit = on;
    ESP_LOGI(TAG, "IoT flag is %s when that device loads the panel",
             on ? "cleared" : "kept");
    return save_flag(NVS_KEY_CLRVIS, on);
}

bool devices_listed_for_guest(const uint8_t target[6], const uint8_t viewer[6])
{
    if (devices_visible(target, viewer)) {
        return true;
    }
    if (!s_guest_claim) {
        return false;
    }
    device_rec_t r;
    /* An IoT device nobody has claimed: shown so it can be claimed, not edited. */
    return devices_get(target, &r) && r.iot && !devices_mac_is_set(r.owner);
}

esp_err_t devices_claim(const uint8_t target[6], const uint8_t owner[6])
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!devices_mac_is_set(target) || !devices_mac_is_set(owner)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(target, owner, 6) == 0) {
        return ESP_ERR_INVALID_ARG;   /* a device cannot own itself */
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = -1;
    for (int i = 0; i < s_view[s_active].count; i++) {
        if (memcmp(s_view[s_active].rec[i].mac, target, 6) == 0) {
            slot = i;
            break;
        }
    }
    bool taken = slot >= 0 && devices_mac_is_set(s_view[s_active].rec[slot].owner);
    uint8_t cur_owner[6] = {0};
    if (taken) {
        memcpy(cur_owner, s_view[s_active].rec[slot].owner, 6);
    }
    xSemaphoreGive(s_lock);

    if (!taken) {
        /* Claim: it must exist and be an IoT device with no owner. */
        device_rec_t r;
        if (devices_get(target, &r) && r.iot) {
            return devices_set_owner(target, owner);
        }
        return ESP_ERR_INVALID_ARG;
    }

    /* Already owned: the holder may release it, nobody else may take it. */
    if (memcmp(cur_owner, owner, 6) == 0) {
        return devices_set_owner(target, NULL);
    }
    return ESP_ERR_INVALID_STATE;   /* someone else's */
}

void devices_clear_iot(const uint8_t mac[6])
{
    device_rec_t r;
    if (!devices_get(mac, &r) || !r.iot) {
        return;   /* nothing to do, and nothing written to NVS */
    }
    ESP_LOGI(TAG, MACSTR " loaded the panel, so it is no longer treated as IoT",
             MAC2STR(mac));
    devices_set_iot(mac, false);
}

int devices_records(device_rec_t *out, int max)
{
    int slot = s_active;
    int n = s_view[slot].count;
    if (out == NULL || max <= 0) {
        return n;
    }
    if (n > max) {
        n = max;
    }
    memcpy(out, s_view[slot].rec, (size_t)n * sizeof(device_rec_t));
    return n;
}

bool devices_get(const uint8_t mac[6], device_rec_t *out)
{
    if (!devices_mac_is_set(mac)) {
        return false;
    }
    int slot = s_active;
    for (int i = 0; i < s_view[slot].count; i++) {
        if (memcmp(s_view[slot].rec[i].mac, mac, 6) == 0) {
            if (out != NULL) {
                *out = s_view[slot].rec[i];
            }
            return true;
        }
    }
    return false;
}

static esp_err_t apply_locked(const uint8_t mac[6], bool iot,
                              const uint8_t *owner, bool change_owner);

esp_err_t devices_set(const uint8_t mac[6], bool iot, const uint8_t *owner)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!devices_mac_is_set(mac)) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = apply_locked(mac, iot, owner, true);
    xSemaphoreGive(s_lock);
    return e;
}

/* Caller holds the lock. Writes `iot`/`owner` into the record for `mac`,
 * creating or dropping it as needed. Used by the three entry points below. */
static esp_err_t apply_locked(const uint8_t mac[6], bool iot,
                              const uint8_t *owner, bool change_owner)
{
    int next = 1 - s_active;
    memcpy(&s_view[next], &s_view[s_active], sizeof(devices_view_t));

    int slot = -1;
    for (int i = 0; i < s_view[next].count; i++) {
        if (memcmp(s_view[next].rec[i].mac, mac, 6) == 0) {
            slot = i;
            break;
        }
    }

    uint8_t final_owner[6] = {0};
    if (change_owner) {
        if (owner != NULL && devices_mac_is_set(owner)) {
            memcpy(final_owner, owner, 6);
        }
    } else if (slot >= 0) {
        memcpy(final_owner, s_view[next].rec[slot].owner, 6);
    }

    if (!iot && !devices_mac_is_set(final_owner)) {
        if (slot >= 0) {
            memmove(&s_view[next].rec[slot], &s_view[next].rec[slot + 1],
                    (size_t)(s_view[next].count - slot - 1) * sizeof(device_rec_t));
            s_view[next].count--;
            persist(next);
            s_active = next;
            ESP_LOGI(TAG, "record for " MACSTR " removed", MAC2STR(mac));
        }
        return ESP_OK;
    }

    if (slot < 0) {
        if (s_view[next].count >= DEVICES_MAX) {
            ESP_LOGE(TAG, "device table full (%d)", DEVICES_MAX);
            return ESP_ERR_NO_MEM;
        }
        slot = s_view[next].count++;
        memset(&s_view[next].rec[slot], 0, sizeof(device_rec_t));
        memcpy(s_view[next].rec[slot].mac, mac, 6);
    }

    /* Skip the write when nothing changes. The visit hook calls this on every
     * request, and committing to NVS each time would wear the flash for no
     * reason. */
    if (s_view[next].rec[slot].iot == iot &&
            memcmp(s_view[next].rec[slot].owner, final_owner, 6) == 0) {
        return ESP_OK;
    }

    s_view[next].rec[slot].iot = iot;
    memcpy(s_view[next].rec[slot].owner, final_owner, 6);

    persist(next);
    s_active = next;   /* single store publishes the whole view */
    ESP_LOGI(TAG, MACSTR " iot=%d owner=" MACSTR, MAC2STR(mac), iot ? 1 : 0,
             MAC2STR(final_owner));
    return ESP_OK;
}

esp_err_t devices_set_iot(const uint8_t mac[6], bool iot)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!devices_mac_is_set(mac)) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = apply_locked(mac, iot, NULL, false);
    xSemaphoreGive(s_lock);
    return e;
}

esp_err_t devices_set_owner(const uint8_t mac[6], const uint8_t *owner)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!devices_mac_is_set(mac)) {
        return ESP_ERR_INVALID_ARG;
    }
    device_rec_t r;
    bool iot_now = devices_get(mac, &r) && r.iot;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = apply_locked(mac, iot_now, owner, true);
    xSemaphoreGive(s_lock);
    return e;
}

bool devices_visible(const uint8_t target[6], const uint8_t viewer[6])
{
    if (!devices_mac_is_set(target) || !devices_mac_is_set(viewer)) {
        return false;
    }
    if (memcmp(target, viewer, 6) == 0) {
        return true;   /* a device always sees itself */
    }
    device_rec_t r;
    if (!devices_get(target, &r)) {
        return false;
    }
    /* Only IoT devices have an owner, and ownership is the sole reason one device
     * can see another. */
    return r.iot && devices_mac_is_set(r.owner) && memcmp(r.owner, viewer, 6) == 0;
}
