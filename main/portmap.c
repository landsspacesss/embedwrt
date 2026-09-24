/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/def.h"          /* ntohl */
#include "lwip/lwip_napt.h"
#include "lwip/prot/ip.h"      /* IP_PROTO_TCP / IP_PROTO_UDP */
#include "nvs.h"

#include "portmap.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY       "pforwards"

static const char *TAG = "portmap";

static portmap_entry_t s_entries[PORTMAP_MAX];
static int s_count;
static SemaphoreHandle_t s_lock;

static void persist(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG, "cannot open NVS");
        return;
    }
    nvs_set_blob(h, NVS_KEY, s_entries, (size_t)s_count * sizeof(portmap_entry_t));
    nvs_commit(h);
    nvs_close(h);
}

void portmap_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    size_t len = sizeof(s_entries);
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, NVS_KEY, s_entries, &len) == ESP_OK &&
                len % sizeof(portmap_entry_t) == 0 &&
                len / sizeof(portmap_entry_t) <= PORTMAP_MAX) {
            s_count = (int)(len / sizeof(portmap_entry_t));
        } else {
            s_count = 0;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "%d forwarding rule(s) loaded", s_count);
}

int portmap_list(portmap_entry_t *out, int max)
{
    if (out == NULL || max <= 0) {
        return 0;
    }
    int n = 0;
    if (s_lock != NULL) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    n = (s_count < max) ? s_count : max;
    memcpy(out, s_entries, (size_t)n * sizeof(portmap_entry_t));
    if (s_lock != NULL) {
        xSemaphoreGive(s_lock);
    }
    return n;
}

/* Runs on the TCPIP thread; see the note in portmap.h. */
typedef struct {
    uint32_t sta_ip;
    const portmap_entry_t *entries;
    int count;
} apply_ctx_t;

/* Also runs on the TCPIP thread: ip_portmap_remove() shifts the whole table
 * down, which must not race with the forwarding path reading it. */
static esp_err_t remove_cb(void *arg)
{
    const portmap_entry_t *e = arg;
    if (!ip_portmap_remove(e->proto, e->mport)) {
        ESP_LOGW(TAG, "lwIP had no mapping for %s/%u",
                 e->proto == IP_PROTO_TCP ? "tcp" : "udp", e->mport);
    }
    return ESP_OK;
}

static esp_err_t apply_cb(void *arg)
{
    apply_ctx_t *c = arg;
    int applied = 0;
    for (int i = 0; i < c->count; i++) {
        const portmap_entry_t *e = &c->entries[i];
        /* Same external port with a different protocol is a distinct mapping;
         * ip_portmap_add keys on (proto, mport), so no conflict there. */
        if (!ip_portmap_add(e->proto, c->sta_ip, e->mport, e->daddr, e->dport)) {
            ESP_LOGW(TAG, "lwIP refused %s/%u -> %u.%u.%u.%u:%u",
                     e->proto == IP_PROTO_TCP ? "tcp" : "udp", e->mport,
                     (unsigned)(e->daddr & 0xFF), (unsigned)((e->daddr >> 8) & 0xFF),
                     (unsigned)((e->daddr >> 16) & 0xFF), (unsigned)((e->daddr >> 24) & 0xFF),
                     e->dport);
            continue;
        }
        applied++;

        /*
         * Read the entry back and confirm it holds what we asked for. This is
         * the only part of the feature that can be verified without a client on
         * the AP to connect to: the packet path itself is lwIP's own portmap
         * code, but the registration, the addresses and the ordering are ours.
         * Being in the TCPIP thread here, reading the table is safe.
         */
        u32_t v_maddr = 0, v_daddr = 0;
        u16_t v_dport = 0;
        if (ip_portmap_get(e->proto, e->mport, &v_maddr, &v_daddr, &v_dport)) {
            if (v_maddr != c->sta_ip || v_daddr != e->daddr || v_dport != e->dport) {
                ESP_LOGE(TAG, "rule %u read back wrong: ext=%08x in=%08x:%u (wanted %08x %08x:%u)",
                         e->mport, (unsigned)v_maddr, (unsigned)v_daddr, v_dport,
                         (unsigned)c->sta_ip, (unsigned)e->daddr, e->dport);
            } else {
                ESP_LOGI(TAG, "rule %s/%u verified: external=%08x -> internal=%08x:%u",
                         e->proto == IP_PROTO_TCP ? "tcp" : "udp", e->mport,
                         (unsigned)v_maddr, (unsigned)v_daddr, v_dport);
            }
        } else {
            ESP_LOGE(TAG, "rule %u not found by read-back", e->mport);
        }
    }
    ESP_LOGI(TAG, "%d/%d rule(s) active", applied, c->count);
    return ESP_OK;
}

esp_err_t portmap_apply_all(uint32_t sta_ip)
{
    if (sta_ip == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    portmap_entry_t snapshot[PORTMAP_MAX];
    int n = portmap_list(snapshot, PORTMAP_MAX);
    if (n == 0) {
        return ESP_OK;
    }
    /* Always re-add, even if the address is unchanged: ip_portmap_add()
     * overwrites the entry for a given (proto, mport), so this is idempotent and
     * costs nothing, while guaranteeing the stored external address is current. */
    apply_ctx_t ctx = { .sta_ip = sta_ip, .entries = snapshot, .count = n };
    return esp_netif_tcpip_exec(apply_cb, &ctx);
}

esp_err_t portmap_add(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport,
                      uint32_t ap_ip, uint32_t netmask)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP) {
        ESP_LOGE(TAG, "protocol must be TCP or UDP");
        return ESP_ERR_INVALID_ARG;
    }
    if (mport == 0 || dport == 0) {
        ESP_LOGE(TAG, "port 0 is not usable");
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t d_h = ntohl(daddr), ap_h = ntohl(ap_ip), mask_h = ntohl(netmask);
    if ((d_h & mask_h) != (ap_h & mask_h)) {
        ESP_LOGE(TAG, "target is not on the AP subnet");
        return ESP_ERR_INVALID_ARG;
    }
    if (d_h == ap_h) {
        ESP_LOGE(TAG, "target is the repeater itself; it needs no forwarding");
        return ESP_ERR_INVALID_ARG;
    }
    if (d_h == (ap_h & mask_h) || d_h == ((ap_h & mask_h) | ~mask_h)) {
        ESP_LOGE(TAG, "target is the network or broadcast address");
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ESP_OK;
    xSemaphoreTake(s_lock, portMAX_DELAY);

    int slot = -1;
    for (int i = 0; i < s_count; i++) {
        /* An external port may serve TCP and UDP separately, but not twice on
         * the same protocol. */
        if (s_entries[i].proto == proto && s_entries[i].mport == mport) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        if (s_count >= PORTMAP_MAX) {
            ESP_LOGE(TAG, "table full (%d)", PORTMAP_MAX);
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        slot = s_count++;
    }
    s_entries[slot].proto = proto;
    s_entries[slot].mport = mport;
    s_entries[slot].daddr = daddr;
    s_entries[slot].dport = dport;
    persist();
    ESP_LOGI(TAG, "%s %u -> %u.%u.%u.%u:%u saved",
             proto == IP_PROTO_TCP ? "tcp" : "udp", mport,
             (unsigned)(daddr & 0xFF), (unsigned)((daddr >> 8) & 0xFF),
             (unsigned)((daddr >> 16) & 0xFF), (unsigned)((daddr >> 24) & 0xFF), dport);

out:
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t portmap_remove(uint8_t proto, uint16_t mport)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    portmap_entry_t removed;
    bool found = false;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        if (s_entries[i].proto == proto && s_entries[i].mport == mport) {
            removed = s_entries[i];
            memmove(&s_entries[i], &s_entries[i + 1],
                    (size_t)(s_count - i - 1) * sizeof(portmap_entry_t));
            s_count--;
            persist();
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_lock);

    if (!found) {
        return ESP_ERR_NOT_FOUND;
    }
    /* Outside the lock: this blocks until the TCPIP thread runs the callback,
     * and holding the table lock across it would stall the HTTP and event
     * tasks for no reason. */
    esp_netif_tcpip_exec(remove_cb, &removed);
    ESP_LOGI(TAG, "removed %s %u", proto == IP_PROTO_TCP ? "tcp" : "udp", mport);
    return ESP_OK;
}
