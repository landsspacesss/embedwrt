/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ESP32-S3 WiFi repeater: creates an AP, joins an upstream network as a
 * station, and NATs between them. Client DNS is answered by a local relay that
 * forwards over DNS-over-HTTPS (see doh_relay.c).
 *
 * Derived from "ESP32 WiFi Pocket" (C) 2026 Ivan Svarkovsky, GPL v3.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mdns.h"
#include "esp_event.h"
#include "esp_sntp.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_http_server.h"
#include "cJSON.h"

#include "ap_dhcp.h"
#include "clients.h"
#include "dns_rules.h"
#include "doh_relay.h"
#include "portmap.h"
#include "static_leases.h"
#include "led_off.h"

#define AP_SSID_PREFIX    "ESPWIFI"
#define AP_MAX_CONN      7
#define AP_PASSWORD_LEN   8    /* length of a freshly generated password */
#define AP_PASSWORD_MAX   64   /* longest password the web UI may set (63 usable) */

/* Reconnect policy: unlimited attempts with exponential backoff. The upstream
 * router may reboot or drop out for minutes; the repeater must come back on its
 * own instead of giving up. */
#define STA_RETRY_FIRST_MS      100
#define STA_RETRY_MIN_MS        1000
#define STA_RETRY_MAX_MS        30000
#define STA_CONNECT_TIMEOUT_MS  15000

#define WIFI_CONNECTED_BIT     BIT0
#define STA_NEED_CONNECT_BIT   BIT1
#define STA_BACKOFF_RESET_BIT  BIT2

#define NVS_NAMESPACE  "storage"

static const char *TAG_MAIN = "router";
static const char *TAG_AP = "wifi_ap";
static const char *TAG_STA = "wifi_sta";

static esp_netif_t *ap_netif = NULL;
static esp_netif_t *sta_netif = NULL;
static EventGroupHandle_t s_wifi_eg = NULL;
static TaskHandle_t s_reconnect_task = NULL;

static volatile bool s_sta_should_connect = false;

static char sta_ssid[33] = {0};
static char sta_password[65] = {0};
static char ap_ssid_full[33] = {0};
static char ap_password[AP_PASSWORD_MAX] = {0};
static char doh_url[DOH_URL_MAX] = DOH_DEFAULT_URL;

/*
 * Radio tuning. The ESP-IDF factory default is
 * {.cc="01", .schan=1, .nchan=11, AUTO} - world-safe mode, restricted to
 * channels 1-11 with a conservative power table, and AUTO meaning the value is
 * inherited from whatever country the upstream AP advertises. The real
 * regulatory domain is pinned instead, so channels, power and our own AP's
 * country IE are correct regardless of the upstream.
 *
 * s_country_at_boot is what the driver reported before this run overrode it.
 * It is NOT the factory default: esp_wifi_set_country* persists to flash, so
 * after the first run that sets CN this reads back "CN". Use it to see what was
 * stored, not to compare against the factory profile - for that, the documented
 * default above is the reference.
 */
static bool s_bw_ht20 = false;   /* false = HT40, which is the driver default */
static wifi_country_t s_country_at_boot;
static bool s_country_at_boot_valid = false;
static int8_t s_txpower_qdbm = 0;   /* quarter-dBm; 80 == 20 dBm */

/* ======================= NVS ======================= */

static void load_wifi_credentials(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t len = sizeof(sta_ssid);
    if (nvs_get_str(h, "ssid", sta_ssid, &len) == ESP_OK) {
        len = sizeof(sta_password);
        if (nvs_get_str(h, "password", sta_password, &len) != ESP_OK) {
            sta_password[0] = '\0';
        }
        ESP_LOGI(TAG_MAIN, "upstream network from NVS: '%s'", sta_ssid);
    }
    nvs_close(h);
}

static void save_wifi_credentials(const char *ssid, const char *password)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "cannot open NVS to save credentials");
        return;
    }
    nvs_set_str(h, "ssid", ssid);
    nvs_set_str(h, "password", password);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG_MAIN, "upstream credentials saved");
}

/* Which DoH resolver to use is network-dependent: several well-known ones are
 * unreachable from mainland China, so this cannot be a compile-time constant. */
static void load_doh_url(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t len = sizeof(doh_url);
    if (nvs_get_str(h, "doh_url", doh_url, &len) == ESP_OK) {
        ESP_LOGI(TAG_MAIN, "DoH resolver from NVS: %s", doh_url);
    } else {
        strncpy(doh_url, DOH_DEFAULT_URL, sizeof(doh_url) - 1);
    }
    nvs_close(h);
}

static void save_doh_url(const char *url)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "cannot open NVS to save the resolver");
        return;
    }
    nvs_set_str(h, "doh_url", url);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG_MAIN, "DoH resolver saved");
}

/*
 * A MAC-derived AP password is guessable: the SSID broadcasts the last two MAC
 * bytes, so anyone in range can compute the rest. Use the hardware RNG instead.
 */
static void generate_ap_password(void)
{
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; /* no I/O/0/1 */
    uint8_t raw[AP_PASSWORD_LEN];
    esp_fill_random(raw, sizeof(raw));
    for (int i = 0; i < AP_PASSWORD_LEN; i++) {
        ap_password[i] = alphabet[raw[i] % (sizeof(alphabet) - 1)];
    }
    ap_password[AP_PASSWORD_LEN] = '\0';
}

/* ======================= radio tuning ======================= */

/*
 * wifi_country_t.cc is char[3] with no terminator, so it must never be handed to
 * a %s or to a JSON string builder directly - doing so reads past the field and
 * emits whatever follows it in the struct.
 */
static void country_cc(const wifi_country_t *c, char out[4])
{
    memcpy(out, c->cc, 3);
    out[3] = '\0';
}

static void load_radio_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    uint8_t v = 0;
    if (nvs_get_u8(h, "bw20", &v) == ESP_OK) {
        s_bw_ht20 = (v != 0);
    }
    nvs_close(h);
}

static void save_radio_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "cannot open NVS to save radio settings");
        return;
    }
    nvs_set_u8(h, "bw20", s_bw_ht20 ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
}

/* Both interfaces must match: the AP is on the station's channel, so a
 * bandwidth mismatch between them would only add airtime contention. */
static void apply_bandwidth(void)
{
    wifi_bandwidth_t bw = s_bw_ht20 ? WIFI_BW20 : WIFI_BW40;
    esp_err_t a = esp_wifi_set_bandwidth(WIFI_IF_STA, bw);
    esp_err_t b = esp_wifi_set_bandwidth(WIFI_IF_AP, bw);
    if (a != ESP_OK || b != ESP_OK) {
        ESP_LOGW(TAG_MAIN, "bandwidth %s not applied (%s / %s)",
                 s_bw_ht20 ? "HT20" : "HT40", esp_err_to_name(a), esp_err_to_name(b));
    } else {
        ESP_LOGI(TAG_MAIN, "bandwidth set to %s", s_bw_ht20 ? "HT20" : "HT40");
    }
}

/* ======================= WiFi config ======================= */

/*
 * Copy a passphrase into one of the driver's fixed 64-byte password fields.
 * `dst` is expected to be zero-initialised, which supplies the terminator for
 * any passphrase shorter than the field. A full 64-character hex PSK is legal
 * and deliberately leaves the field unterminated, so this must not force a NUL
 * the way strncpy/snprintf into a 64-byte buffer would.
 */
static void set_wifi_password(uint8_t *dst, size_t dst_sz, const char *src)
{
    size_t len = strlen(src);
    if (len > dst_sz) {
        len = dst_sz;
    }
    memcpy(dst, src, len);
}

static esp_err_t apply_ap_config(void)
{
    wifi_config_t c = {0};

    size_t len = strlen(ap_ssid_full);
    if (len > sizeof(c.ap.ssid)) {
        len = sizeof(c.ap.ssid);
    }
    memcpy(c.ap.ssid, ap_ssid_full, len);
    c.ap.ssid_len = (uint8_t)len;
    c.ap.channel = 0; /* let the driver keep the AP on the station's channel */
    c.ap.max_connection = AP_MAX_CONN;
    c.ap.pmf_cfg.capable = true;
    c.ap.pmf_cfg.required = false;

    if (strlen(ap_password) > 0) {
        c.ap.authmode = WIFI_AUTH_WPA2_PSK;
        set_wifi_password(c.ap.password, sizeof(c.ap.password), ap_password);
    } else {
        c.ap.authmode = WIFI_AUTH_OPEN;
    }
    return esp_wifi_set_config(WIFI_IF_AP, &c);
}

static esp_err_t apply_sta_config(void)
{
    wifi_config_t c = {0};

    size_t len = strlen(sta_ssid);
    if (len > sizeof(c.sta.ssid)) {
        len = sizeof(c.sta.ssid);
    }
    memcpy(c.sta.ssid, sta_ssid, len);
    set_wifi_password(c.sta.password, sizeof(c.sta.password), sta_password);

    c.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    c.sta.failure_retry_cnt = 3;
    c.sta.threshold.authmode = WIFI_AUTH_OPEN;
    c.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    return esp_wifi_set_config(WIFI_IF_STA, &c);
}

/*
 * Point the AP's DHCP server at ourselves. Clients must use the local relay as
 * their resolver, otherwise they would query the upstream DNS directly and
 * bypass DoH entirely.
 */
/* The DHCP server (and with it, the DNS address handed to clients) lives in
 * ap_dhcp.c so the IDF and vendored implementations stay side by side. */

/* ======================= event handling ======================= */

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = event_data;
        ESP_LOGI(TAG_AP, "client " MACSTR " joined, aid=%d", MAC2STR(e->mac), e->aid);
        clients_note_join(e->mac);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = event_data;
        ESP_LOGI(TAG_AP, "client " MACSTR " left, aid=%d, reason=%d",
                 MAC2STR(e->mac), e->aid, e->reason);
        clients_note_leave(e->mac);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG_STA, "station started");
        if (s_sta_should_connect) {
            /* Interrupt any pending backoff: e.g. right after a config change. */
            xEventGroupSetBits(s_wifi_eg, STA_BACKOFF_RESET_BIT | STA_NEED_CONNECT_BIT);
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *e = event_data;
        ESP_LOGW(TAG_STA, "disconnected, reason=%d", e->reason);
        xEventGroupClearBits(s_wifi_eg, WIFI_CONNECTED_BIT);
        if (s_sta_should_connect) {
            xEventGroupSetBits(s_wifi_eg, STA_NEED_CONNECT_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = event_data;
        ESP_LOGI(TAG_STA, "got IP: " IPSTR, IP2STR(&e->ip_info.ip));
        esp_netif_set_default_netif(sta_netif);
        if (esp_netif_napt_enable(ap_netif) != ESP_OK) {
            ESP_LOGE(TAG_STA, "could not enable NAPT on the AP interface");
        } else {
            ESP_LOGI(TAG_STA, "NAPT enabled on the AP interface");
        }
        /* Re-push the forwarding rules: they store the external address as it
         * was when they were created, so a new lease invalidates them. Must
         * follow the NAPT enable, which is what allocates lwIP's portmap table. */
        portmap_apply_all(e->ip_info.ip.addr);
        doh_relay_flush_cache(); /* the upstream network may have changed */
        xEventGroupSetBits(s_wifi_eg, WIFI_CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ASSIGNED_IP_TO_CLIENT) {
        /* Emitted by IDF's DHCP server. When the vendored one is in use this
         * never fires; AP_DHCP_EVENT below carries the same information. */
        const ip_event_assigned_ip_to_client_t *e = event_data;
        ESP_LOGI(TAG_AP, "assigned " IPSTR " to " MACSTR " (%s)",
                 IP2STR(&e->ip), MAC2STR(e->mac), e->hostname);
        clients_note_ip(e->mac, e->ip, e->hostname);
    } else if (event_base == AP_DHCP_EVENT && event_id == AP_DHCP_EV_LEASE) {
        /* Runs on the event loop task, not the lwIP thread, which is the whole
         * point of the vendored server posting an event instead of doing this
         * in its callback. */
        const ap_dhcp_lease_t *e = event_data;
        ESP_LOGI(TAG_AP, "assigned " IPSTR " to " MACSTR "%s%s",
                 IP2STR(&e->ip), MAC2STR(e->mac),
                 e->hostname[0] ? " host=" : "", e->hostname);
        clients_note_ip(e->mac, e->ip, e->hostname);
        /* Keeps the DNS relay's IP->rule map current: it only ever sees a
         * query's source address, not the MAC. */
        dns_rules_note_ip(e->mac, e->ip.addr);
    }
}

static void sta_reconnect_task(void *arg)
{
    int delay_ms = STA_RETRY_FIRST_MS;

    for (;;) {
        xEventGroupWaitBits(s_wifi_eg, STA_NEED_CONNECT_BIT, pdTRUE, pdFALSE, portMAX_DELAY);
        delay_ms = STA_RETRY_FIRST_MS;

        while (s_sta_should_connect) {
            if (xEventGroupGetBits(s_wifi_eg) & WIFI_CONNECTED_BIT) {
                break;
            }

            /* Wait out the backoff, but wake early if the config changed. */
            EventBits_t w = xEventGroupWaitBits(s_wifi_eg, STA_BACKOFF_RESET_BIT,
                                                pdTRUE, pdFALSE, pdMS_TO_TICKS(delay_ms));
            if (w & STA_BACKOFF_RESET_BIT) {
                delay_ms = STA_RETRY_FIRST_MS;
            }
            if (!s_sta_should_connect ||
                    (xEventGroupGetBits(s_wifi_eg) & WIFI_CONNECTED_BIT)) {
                break;
            }

            ESP_LOGI(TAG_STA, "connecting to '%s'", sta_ssid);
            esp_err_t err = esp_wifi_connect();
            if (err != ESP_OK) {
                ESP_LOGW(TAG_STA, "esp_wifi_connect: %s", esp_err_to_name(err));
            }

            EventBits_t b = xEventGroupWaitBits(s_wifi_eg, WIFI_CONNECTED_BIT,
                                               pdFALSE, pdFALSE,
                                               pdMS_TO_TICKS(STA_CONNECT_TIMEOUT_MS));
            if (b & WIFI_CONNECTED_BIT) {
                delay_ms = STA_RETRY_FIRST_MS;
                break;
            }

            if (delay_ms < STA_RETRY_MIN_MS) {
                delay_ms = STA_RETRY_MIN_MS;
            } else if (delay_ms < STA_RETRY_MAX_MS) {
                delay_ms *= 2;
                if (delay_ms > STA_RETRY_MAX_MS) {
                    delay_ms = STA_RETRY_MAX_MS;
                }
            }
            ESP_LOGW(TAG_STA, "still not connected, retrying in %d ms", delay_ms);
        }
    }
}

/* ======================= mDNS ======================= */

/*
 * Advertise a name for the web interface.
 *
 * mDNS rather than an entry in our own DNS relay, for a specific reason: a name
 * served by the relay would only resolve for clients whose queries go through
 * it, and a device pinned to a per-device DoT or plaintext rule bypasses the
 * relay entirely - so that approach would silently fail for exactly those
 * clients. mDNS is a separate protocol on its own multicast port and is
 * indifferent to which resolver a client uses.
 *
 * `.local` is the TLD RFC 6762 reserves for mDNS, so this is the correct use of
 * it; serving `.local` from a unicast resolver would be a spec violation and
 * misfires on mDNS-aware clients. Both netifs are covered by default (the
 * component's PREDEF_NETIF_STA/AP default on): the station advertises this
 * device's upstream address and the AP advertises 192.168.4.1.
 */
static char s_mdns_host[33] = "espwifi";

static void load_mdns_host(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t len = sizeof(s_mdns_host);
    if (nvs_get_str(h, "mdns_host", s_mdns_host, &len) != ESP_OK) {
        strncpy(s_mdns_host, "espwifi", sizeof(s_mdns_host) - 1);
    }
    nvs_close(h);
}

static void save_mdns_host(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "cannot open NVS to save the mDNS name");
        return;
    }
    nvs_set_str(h, "mdns_host", s_mdns_host);
    nvs_commit(h);
    nvs_close(h);
}

/* A DNS label: letters, digits and hyphens, not starting or ending with one. */
static bool valid_hostname(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-';
        if (!ok) {
            return false;
        }
        if (c == '-' && (i == 0 || i == n - 1)) {
            return false;
        }
    }
    return true;
}

static void start_mdns(void)
{
    if (mdns_init() != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "mdns_init failed; the name will not resolve");
        return;
    }
    if (mdns_hostname_set(s_mdns_host) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "mdns_hostname_set('%s') failed", s_mdns_host);
        return;
    }
    /* Advertise the web interface too, so it shows up in mDNS service browsers
     * rather than only resolving by name. */
    mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    ESP_LOGI(TAG_MAIN, "mDNS: http://%s.local/", s_mdns_host);
}

/* ======================= SNTP ======================= */

static void sntp_sync_cb(struct timeval *tv)
{
    ESP_LOGI(TAG_MAIN, "clock synced (epoch %ld), DoH can now validate certificates",
             (long)tv->tv_sec);
    doh_relay_set_time_synced(true);
}

static void start_sntp(void)
{
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    /* Literal IPs on purpose: DoH needs a valid clock, so time must not depend
     * on resolving a hostname first. */
    esp_sntp_setservername(0, "162.159.200.1"); /* time.cloudflare.com */
    esp_sntp_setservername(1, "216.239.35.0");  /* time.google.com */
    esp_sntp_set_time_sync_notification_cb(sntp_sync_cb);
    esp_sntp_init();
}

/* ======================= web interface ======================= */

static const char *html_page =
"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>ESP32 Repeater</title>"
"<link rel='icon' href='data:,'>"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:center;min-height:100vh;color:#1e293b}"
".card{background:#fff;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:100%;max-width:400px;overflow:hidden}"
".header{background:linear-gradient(135deg,#1e293b,#334155);padding:20px 24px;text-align:center;color:#fff}"
".header-icon{margin-bottom:8px}"
".header-icon svg{width:32px;height:32px;fill:#60a5fa}"
".header h1{font-size:18px;font-weight:700;color:#f1f5f9;letter-spacing:0.5px}"
".header .subtitle{font-size:11px;color:#94a3b8;margin-top:4px}"
".tabs{display:flex;border-bottom:1px solid #e2e8f0}"
".tab{flex:1;text-align:center;padding:14px;font-size:13px;font-weight:600;color:#64748b;background:#f8fafc;border:none;cursor:pointer;transition:all 0.2s}"
".tab.active{color:#3b82f6;background:#fff;border-bottom:2px solid #3b82f6}"
".tab-content{display:none;padding:24px}"
".tab-content.active{display:block}"
".header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}"
"h1{font-size:20px;color:#0f172a}"
".refresh-btn{background:#e2e8f0;color:#475569;border:none;padding:8px 12px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;transition:0.2s}"
".refresh-btn:hover{background:#cbd5e1}"
"#status-msg{text-align:center;font-size:13px;margin-bottom:8px;font-weight:500;padding:8px;border-radius:6px;background:#f8fafc}"
"#dns-msg{text-align:center;font-size:12px;margin-bottom:15px;color:#64748b}"
".network-list{border:1px solid #e2e8f0;border-radius:8px;margin-bottom:20px;max-height:200px;overflow-y:auto;background:#fafafa}"
".network-item{display:flex;justify-content:space-between;align-items:center;padding:10px 15px;border-bottom:1px solid #e2e8f0;cursor:pointer;transition:background 0.2s}"
".network-item:last-child{border-bottom:none}"
".network-item:hover{background:#f1f5f9}"
".net-info{display:flex;align-items:center;gap:10px;font-size:14px;color:#334155}"
".net-icons{display:flex;align-items:center;gap:6px}"
".icon{width:16px;height:16px}"
".icon.secure{fill:#94a3b8}"
".form-group{margin-bottom:15px}"
"label{display:block;font-size:13px;color:#475569;margin-bottom:6px;font-weight:500}"
"input{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px;outline:none;transition:border 0.2s}"
"input:focus{border-color:#3b82f6}"
".btn{width:100%;background:#3b82f6;color:white;border:none;padding:12px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;transition:0.2s;margin-top:5px}"
".btn:hover{background:#2563eb}"
".btn.danger{background:#ef4444}"
".btn.danger:hover{background:#dc2626}"
".loading{text-align:center;padding:20px;font-size:14px;color:#64748b}"
".info-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px;margin-bottom:15px;font-size:13px;color:#166534}"
".info-box.warn{background:#fef2f2;border-color:#fecaca;color:#991b1b}"
".footer{margin-top:20px;padding-top:15px;border-top:1px solid #e2e8f0;text-align:center;font-size:11px;color:#94a3b8}"
".footer-line{margin-bottom:3px}"
".footer a{color:#64748b;text-decoration:none}"
".footer a:hover{text-decoration:underline}"
"</style></head><body>"
"<div class='card'>"
"  <div class='header'>"
"    <div class='header-icon'>"
"      <svg viewBox='0 0 24 24'><path d='M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z'/></svg>"
"    </div>"
"    <h1>ESP32 Repeater</h1>"
"    <div class='subtitle'>WiFi NAT router &middot; DNS over HTTPS</div>"
"  </div>"
"  <div class='tabs'>"
"    <button class='tab active' onclick='switchTab(\"wifi\")'>WiFi Setup</button>"
"    <button class='tab' onclick='switchTab(\"clients\")'>Clients</button>"
"    <button class='tab' onclick='switchTab(\"settings\")'>Settings</button>"
"  </div>"
"  <div id='tab-wifi' class='tab-content active'>"
"    <div class='header-row'><h1>WiFi Setup</h1><button class='refresh-btn' onclick='scan()'>Refresh</button></div>"
"    <div id='status-msg'>Checking status...</div>"
"    <div id='dns-msg'></div>"
"    <div class='network-list' id='list'><div class='loading'>Scanning networks...</div></div>"
"    <div class='form-group'><label>SSID</label><input type='text' id='ssid' placeholder='Network Name'></div>"
"    <div class='form-group'><label>Password</label><input type='password' id='pwd' placeholder='Password (optional)'></div>"
"    <button class='btn' onclick='connect()'>CONNECT</button>"
"  </div>"
"  <div id='tab-clients' class='tab-content'>"
"    <div class='header-row'><h1>Clients</h1><button class='refresh-btn' onclick='loadClients()'>Refresh</button></div>"
"    <div style='font-size:11px;color:#94a3b8;margin-bottom:12px'>Signal is measured at this device, i.e. how well the client reaches the repeater. Per-client traffic volume is not tracked by the WiFi driver.</div>"
"    <div id='client-list'><div class='loading'>Loading...</div></div>"
"  </div>"
"  <div id='tab-settings' class='tab-content'>"
"    <h1 style='margin-bottom:15px'>Router Settings</h1>"
"    <div class='form-group'><label>Current AP Password</label><input type='text' id='current-pass' readonly></div>"
"    <div class='form-group'><label>New Password</label><input type='text' id='new-pass' placeholder='New password (min 8 chars)'></div>"
"    <button class='btn' onclick='changePass()'>CHANGE PASSWORD</button>"
"    <div id='settings-msg' style='margin-top:12px;font-size:13px;text-align:center'></div>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <h1 style='margin-bottom:6px'>DNS over HTTPS</h1>"
"    <div style='font-size:11px;color:#94a3b8;margin-bottom:12px'>Not every resolver is reachable from every network. If the status below says fallback, try another one.</div>"
"    <div class='form-group'><label>Resolver URL</label><input type='text' id='doh-url' placeholder='https://223.5.5.5/dns-query'></div>"
"    <button class='btn' onclick='saveDoh()'>SAVE RESOLVER</button>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <h1 style='margin-bottom:6px'>Radio</h1>"
"    <div style='font-size:11px;color:#94a3b8;margin-bottom:12px'>HT40 is faster on clean spectrum. HT20 uses half the airtime and needs less signal margin, which can hold up better for distant clients. Worth testing from where you actually use it.</div>"
"    <div class='form-group'><label>Channel width</label>"
"      <select id='bw-sel' style='width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px'>"
"        <option value='20'>20 MHz (HT20)</option>"
"        <option value='40'>40 MHz (HT40)</option>"
"      </select></div>"
"    <button class='btn' onclick='saveRadio()'>APPLY</button>"
"    <div id='radio-state' style='margin-top:10px;font-size:12px;color:#64748b'></div>"
"    <div id='doh-state' style='margin-top:10px;font-size:12px;color:#64748b'></div>"
"    <div id='doh-suggest' style='margin-top:8px;font-size:11px;color:#94a3b8'></div>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <h1 style='margin-bottom:6px'>Per-device DNS</h1>"
"    <div style='font-size:11px;color:#94a3b8;margin-bottom:12px'>Point one device at its own resolver, by MAC. Devices with no rule use the resolver above. DoH wants an <code>https://</code> URL; DoT and plain DNS want an IPv4 literal, <code>IP</code> or <code>IP:port</code>.</div>"
"    <div id='dr-list'><div class='loading'>Loading...</div></div>"
"    <div class='form-group'><label>Device MAC</label><input type='text' id='dr-mac' placeholder='aa:bb:cc:dd:ee:ff'></div>"
"    <div class='form-group'><label>Protocol</label>"
"      <select id='dr-mode' style='width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px'>"
"        <option value='doh'>DoH (https:// URL)</option>"
"        <option value='dot'>DoT (IP, default port 853)</option>"
"        <option value='dns'>Plain DNS (IP, default port 53)</option>"
"      </select></div>"
"    <div class='form-group'><label>Resolver address</label><input type='text' id='dr-addr' placeholder='https://1.12.12.12/dns-query  or  223.5.5.5'></div>"
"    <button class='btn' onclick='addDnsRule()'>SAVE RULE</button>"
"    <button class='btn' style='background:#0f766e;margin-top:8px' onclick='runDnsTest()'>TEST ALL RESOLVERS</button>"
"    <div id='dr-msg' style='margin-top:10px;font-size:12px'></div>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <h1 style='margin-bottom:6px'>Static leases</h1>"
"    <div style='font-size:11px;color:#94a3b8;margin-bottom:12px'>Bind a MAC to a fixed address. Must be outside the dynamic pool, or the allocator could hand the same address to someone else.</div>"
"    <div id='lease-list'><div class='loading'>Loading...</div></div>"
"    <div class='form-group'><label>MAC</label><input type='text' id='lease-mac' placeholder='aa:bb:cc:dd:ee:ff'></div>"
"    <div class='form-group'><label>IP</label><input type='text' id='lease-ip' placeholder='192.168.4.150'></div>"
"    <button class='btn' onclick='addLease()'>ADD LEASE</button>"
"    <div id='lease-msg' style='margin-top:10px;font-size:12px'></div>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <h1 style='margin-bottom:6px'>Port forwarding</h1>"
"    <div id='pm-note' style='font-size:11px;color:#94a3b8;margin-bottom:12px'>Open one port on the upstream side and send it to a client behind this AP.</div>"
"    <div id='pm-list'><div class='loading'>Loading...</div></div>"
"    <div class='form-group'><label>Protocol</label>"
"      <select id='pm-proto' style='width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px'>"
"        <option value='tcp'>TCP</option><option value='udp'>UDP</option></select></div>"
"    <div class='form-group'><label>External port (on the upstream side)</label><input type='text' id='pm-mport' placeholder='8080'></div>"
"    <div class='form-group'><label>Target client IP</label><input type='text' id='pm-daddr' placeholder='192.168.4.150'></div>"
"    <div class='form-group'><label>Target port</label><input type='text' id='pm-dport' placeholder='80'></div>"
"    <button class='btn' onclick='addPortmap()'>ADD RULE</button>"
"    <div id='pm-msg' style='margin-top:10px;font-size:12px'></div>"
"    <hr style='margin:24px 0;border-color:#e2e8f0'>"
"    <button class='btn danger' onclick='resetAP()'>FACTORY RESET AP</button>"
"    <div style='margin-top:8px;font-size:11px;color:#94a3b8'>Resets the AP password to a new random value</div>"
"  </div>"
"  <div class='footer'>"
"    <div class='footer-line'>ESP-IDF 6.1 &nbsp;|&nbsp; <a href='https://github.com/Svarkovsky/esp32-wifi-pocket' target='_blank'>based on esp32-wifi-pocket</a></div>"
"    <div class='footer-line'>GPL v3</div>"
"  </div>"
"</div>"
"<script>"
"const lockSvg='<svg class=\"icon secure\" viewBox=\"0 0 24 24\"><path d=\"M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z\"/></svg>';"
"const wifiSvg='<svg class=\"icon\" viewBox=\"0 0 24 24\"><path d=\"M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z\"/></svg>';"
"let curSsid='';"
"function switchTab(tab){"
"  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));"
"  document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));"
"  event.target.classList.add('active');"
"  document.getElementById('tab-'+tab).classList.add('active');"
"  if(tab==='settings'){ loadSettings(); loadDoh(); loadRadio(); loadDnsRules(); loadLeases(); loadPortmaps(); }"
"  if(tab==='clients'){ loadClients(); }"
"}"
"function bars(rssi){"
"  if(rssi>=-50) return '▂▄▆█'; if(rssi>=-60) return '▂▄▆_';"
"  if(rssi>=-70) return '▂▄__'; if(rssi>=-80) return '▂___'; return '____';"
"}"
"function fmtUp(s){"
"  if(!s) return '-';"
"  if(s<60) return s+'s';"
"  if(s<3600) return Math.floor(s/60)+'m'+(s%60)+'s';"
"  return Math.floor(s/3600)+'h'+Math.floor((s%3600)/60)+'m';"
"}"
"function loadClients(){"
"  const box=document.getElementById('client-list');"
"  box.innerHTML='<div class=\"loading\">Loading...</div>';"
"  fetch('/api/clients').then(r=>r.json()).then(list=>{"
"    if(!list.length) { box.innerHTML='<div class=\"loading\">No clients connected</div>'; return; }"
"    let h='<div class=\"network-list\" style=\"max-height:none\">';"
"    list.forEach(c=>{"
"      const name = c.host ? c.host : '(no hostname)';"
"      const col = c.rssi>=-60 ? '#15803d' : (c.rssi>=-70 ? '#b45309' : '#b91c1c');"
"      h += '<div class=\"network-item\" style=\"display:block\">'"
"         + '<div style=\"display:flex;justify-content:space-between;align-items:center\">'"
"         + '<span class=\"net-info\"><b>'+name+'</b></span>'"
"         + '<span style=\"color:'+col+';font-family:monospace;font-size:13px\">'+bars(c.rssi)+' '+c.rssi+' dBm</span>'"
"         + '</div>'"
"         + '<div style=\"font-size:11px;color:#64748b;margin-top:4px;font-family:monospace\">'"
"         + c.ip + ' &middot; ' + c.mac + ' &middot; up ' + fmtUp(c.uptime)"
"         + '</div></div>';"
"    });"
"    box.innerHTML = h + '</div>';"
"  }).catch(()=>box.innerHTML='<div class=\"loading\">Failed to load</div>');"
"}"
"function loadDnsRules(){"
"  const box=document.getElementById('dr-list');"
"  fetch('/api/dnsrules').then(r=>r.json()).then(d=>{"
"    if(!d.rules.length){ box.innerHTML='<div class=\"loading\">No per-device rules</div>'; return; }"
"    let h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.rules.forEach(r=>{"
"      h += '<div class=\"network-item\" style=\"display:block\">'"
"         + '<div style=\"display:flex;justify-content:space-between;align-items:center\">'"
"         + '<span style=\"font-family:monospace;font-size:12px\"><b>'+r.mode+'</b> '+r.addr+'<br><span style=\"color:#64748b\">'+r.mac+'</span></span>'"
"         + '<button class=\"refresh-btn\" onclick=\"delDnsRule(\\''+r.mac+'\\')\">delete</button>'"
"         + '</div></div>';"
"    });"
"    box.innerHTML = h + '</div>';"
"  }).catch(()=>box.innerHTML='<div class=\"loading\">Failed to load</div>');"
"}"
"function addDnsRule(){"
"  const mac=document.getElementById('dr-mac').value.trim();"
"  const mode=document.getElementById('dr-mode').value;"
"  const addr=document.getElementById('dr-addr').value.trim();"
"  const m=document.getElementById('dr-msg');"
"  if(!mac||!addr){ m.innerHTML='<span style=\"color:#b45309\">Enter both MAC and address</span>'; return; }"
"  fetch('/dnsrule/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&mode='+mode+'&addr='+encodeURIComponent(addr)})"
"  .then(r=>r.text().then(t=>{"
"    m.innerHTML = r.ok ? '<span style=\"color:#15803d\">Rule saved.</span>'"
"                       : '<span style=\"color:#b91c1c\">Rejected: '+t+'</span>';"
"    if(r.ok){ document.getElementById('dr-mac').value=''; document.getElementById('dr-addr').value=''; }"
"    loadDnsRules();"
"  }));"
"}"
"function delDnsRule(mac){"
"  if(!confirm('Remove the DNS rule for '+mac+'?')) return;"
"  fetch('/dnsrule/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})"
"  .then(()=>loadDnsRules());"
"}"
"function runDnsTest(){"
"  const m=document.getElementById('dr-msg');"
"  m.innerHTML='<span style=\"color:#64748b\">Testing each resolver with a real query, this can take ~10s per DoT/DoH entry...</span>';"
"  fetch('/api/dnstest').then(r=>r.json()).then(d=>{"
"    let h='<div style=\"font-family:monospace;font-size:11px;line-height:1.6\">';"
"    h += '<b>default</b> (doh) '+d.default.addr+'<br>&nbsp;&nbsp;'+d.default.result+'<br>';"
"    d.rules.forEach(r=>{ h += '<b>'+r.mac+'</b> ('+r.mode+') '+r.addr+'<br>&nbsp;&nbsp;'+r.result+'<br>'; });"
"    m.innerHTML = h + '</div>';"
"  }).catch(e=>m.innerHTML='<span style=\"color:#b91c1c\">Test request failed</span>');"
"}"
"function loadPortmaps(){"
"  const box=document.getElementById('pm-list');"
"  fetch('/api/portmaps').then(r=>r.json()).then(d=>{"
"    document.getElementById('pm-note').innerHTML = d.external"
"      ? 'Reachable from the upstream network at <b>'+d.external+'</b>. Not reachable from the internet unless the upstream router also forwards it here.'"
"      : 'No upstream address yet.';"
"    if(!d.rules.length){ box.innerHTML='<div class=\"loading\">No rules</div>'; return; }"
"    let h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.rules.forEach(r=>{"
"      h += '<div class=\"network-item\" style=\"display:block\">'"
"         + '<div style=\"display:flex;justify-content:space-between;align-items:center\">'"
"         + '<span style=\"font-family:monospace;font-size:13px\"><b>'+r.proto+' '+r.mport+'</b> &rarr; '+r.daddr+':'+r.dport+'</span>'"
"         + '<button class=\"refresh-btn\" onclick=\"delPortmap(\\''+r.proto+'\\','+r.mport+')\">delete</button>'"
"         + '</div></div>';"
"    });"
"    box.innerHTML = h + '</div>';"
"  }).catch(()=>box.innerHTML='<div class=\"loading\">Failed to load</div>');"
"}"
"function addPortmap(){"
"  const p=document.getElementById('pm-proto').value;"
"  const mp=document.getElementById('pm-mport').value.trim();"
"  const da=document.getElementById('pm-daddr').value.trim();"
"  const dp=document.getElementById('pm-dport').value.trim();"
"  const m=document.getElementById('pm-msg');"
"  if(!mp||!da||!dp){ m.innerHTML='<span style=\"color:#b45309\">Fill in port, target IP and target port</span>'; return; }"
"  fetch('/portmap/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+p+'&mport='+encodeURIComponent(mp)+'&daddr='+encodeURIComponent(da)+'&dport='+encodeURIComponent(dp)})"
"  .then(r=>r.text().then(t=>{"
"    m.innerHTML = r.ok ? '<span style=\"color:#15803d\">Rule added and active.</span>'"
"                       : '<span style=\"color:#b91c1c\">Rejected: '+t+'</span>';"
"    if(r.ok){ document.getElementById('pm-mport').value=''; document.getElementById('pm-daddr').value=''; document.getElementById('pm-dport').value=''; }"
"    loadPortmaps();"
"  }));"
"}"
"function delPortmap(proto,mport){"
"  if(!confirm('Remove '+proto+' '+mport+'?')) return;"
"  fetch('/portmap/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+proto+'&mport='+mport})"
"  .then(()=>loadPortmaps());"
"}"
"function loadLeases(){"
"  const box=document.getElementById('lease-list');"
"  fetch('/api/leases').then(r=>r.json()).then(d=>{"
"    const pool = d.pool_known ? ('Free range: <b>'+d.pool_first+' - '+d.pool_last+'</b> is in use by the pool; pick something outside it, e.g. 192.168.4.150') : 'Pool bounds unknown; adding leases is disabled.';"
"    if(!d.leases.length){ box.innerHTML='<div class=\"loading\">No static leases</div>'; document.getElementById('lease-msg').innerHTML=pool; return; }"
"    let h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.leases.forEach(l=>{"
"      h += '<div class=\"network-item\" style=\"display:block\">'"
"         + '<div style=\"display:flex;justify-content:space-between;align-items:center\">'"
"         + '<span style=\"font-family:monospace;font-size:13px\"><b>'+l.ip+'</b> &rarr; '+l.mac+'</span>'"
"         + '<button class=\"refresh-btn\" onclick=\"delLease(\\''+l.mac+'\\')\">delete</button>'"
"         + '</div></div>';"
"    });"
"    box.innerHTML = h + '</div>';"
"    document.getElementById('lease-msg').innerHTML=pool;"
"  }).catch(()=>box.innerHTML='<div class=\"loading\">Failed to load</div>');"
"}"
"function addLease(){"
"  const mac=document.getElementById('lease-mac').value.trim();"
"  const ip=document.getElementById('lease-ip').value.trim();"
"  const m=document.getElementById('lease-msg');"
"  if(!mac||!ip) { m.innerHTML='<span style=\"color:#b45309\">Enter both MAC and IP</span>'; return; }"
"  fetch('/lease/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&ip='+encodeURIComponent(ip)})"
"  .then(r=>r.text().then(t=>{"
"    m.innerHTML = r.ok ? '<span style=\"color:#15803d\">Lease added. The client picks it up on its next request.</span>'"
"                       : '<span style=\"color:#b91c1c\">Rejected: '+t+'</span>';"
"    if(r.ok){ document.getElementById('lease-mac').value=''; document.getElementById('lease-ip').value=''; }"
"    loadLeases();"
"  }));"
"}"
"function delLease(mac){"
"  if(!confirm('Remove the lease for '+mac+'?')) return;"
"  fetch('/lease/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})"
"  .then(()=>loadLeases());"
"}"
"function loadRadio(){"
"  fetch('/api/radio').then(r=>r.json()).then(d=>{"
"    document.getElementById('bw-sel').value = (d.bw === 'HT20') ? '20' : '40';"
"    document.getElementById('radio-state').innerHTML ="
"      'Country <b>'+d.country+'</b> &middot; channels '+d.ch_min+'-'+d.ch_max"
"      + ' &middot; TX <b>'+d.txpower_dbm+' dBm</b>';"
"  }).catch(()=>{});"
"}"
"function saveRadio(){"
"  const bw=document.getElementById('bw-sel').value;"
"  const btn=event.target; btn.innerText='APPLYING...'; btn.style.background='#94a3b8';"
"  fetch('/setradio',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'bw='+bw})"
"  .then(r=>{"
"    if(r.ok){ document.getElementById('settings-msg').innerHTML='<div class=\"info-box\">Channel width set to '+bw+' MHz.</div>'; }"
"    else { document.getElementById('settings-msg').innerHTML='<div class=\"info-box warn\">Rejected.</div>'; }"
"  })"
"  .finally(()=>{btn.innerText='APPLY'; btn.style.background='#3b82f6'; loadRadio();});"
"}"
"function loadDoh(){"
"  fetch('/api/dohurl').then(r=>r.json()).then(d=>{"
"    document.getElementById('doh-url').value = d.url;"
"    const s=document.getElementById('doh-state');"
"    const good = d.mode === 'doh';"
"    s.innerHTML = 'Status: <b>' + d.mode + '</b>';"
"    s.style.color = good ? '#15803d' : '#b45309';"
"    document.getElementById('doh-suggest').innerHTML ="
"      'Reachable from CN: <b>223.5.5.5</b>, <b>1.12.12.12</b>, <b>doh.pub</b>' +"
"      '<br>Usually blocked: 1.1.1.1, 8.8.8.8, 9.9.9.9';"
"  }).catch(()=>{});"
"}"
"function saveDoh(){"
"  const u=document.getElementById('doh-url').value.trim();"
"  if(!u.startsWith('https://')) return alert('URL must start with https://');"
"  const btn=event.target; btn.innerText='SAVING...'; btn.style.background='#94a3b8';"
"  fetch('/setdohurl',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(u)})"
"  .then(r=>{"
"    if(r.ok){ document.getElementById('settings-msg').innerHTML='<div class=\"info-box\">Resolver saved. New lookups will use it.</div>'; }"
"    else { document.getElementById('settings-msg').innerHTML='<div class=\"info-box warn\">Rejected: must be a valid https:// URL.</div>'; }"
"  })"
"  .finally(()=>{btn.innerText='SAVE RESOLVER'; btn.style.background='#3b82f6'; loadDoh();});"
"}"
"function init(){"
"  fetch('/status').then(r=>r.json()).then(d=>{"
"    curSsid = d.ssid;"
"    const msg = document.getElementById('status-msg');"
"    if(d.status === 'connected') {"
"      msg.innerHTML = 'Connected to: <b>' + d.ssid + '</b>';"
"      msg.style.color = '#15803d'; msg.style.background = '#f0fdf4';"
"    } else {"
"      msg.innerHTML = 'Not connected';"
"      msg.style.color = '#b91c1c'; msg.style.background = '#fef2f2';"
"    }"
"    const dm = document.getElementById('dns-msg');"
"    dm.innerHTML = 'DNS: ' + d.doh + (d.doh === 'doh' ? ' ✓' : '');"
"    scan();"
"  });"
"}"
"function scan(){"
"  const lst=document.getElementById('list'); lst.innerHTML='<div class=\"loading\">Scanning...</div>';"
"  fetch('/scan').then(r=>r.json()).then(data=>{"
"    lst.innerHTML='';"
"    if(data.length===0) return lst.innerHTML='<div class=\"loading\">No networks</div>';"
"    data.forEach(net=>{"
"      const div=document.createElement('div'); div.className='network-item';"
"      if(net.ssid === curSsid) { div.style.background='#f0fdf4'; div.style.borderLeft='3px solid #22c55e'; }"
"      div.onclick=()=>document.getElementById('ssid').value=net.ssid;"
"      div.innerHTML=`<div class='net-info'>${net.ssid} ${net.ssid===curSsid?'<b>(Active)</b>':''}</div><div class='net-icons'>${net.sec?lockSvg:''}${wifiSvg}</div>`;"
"      lst.appendChild(div);"
"    });"
"  }).catch(()=>lst.innerHTML='<div class=\"loading\">Scan failed</div>');"
"}"
"function connect(){"
"  const s=document.getElementById('ssid').value;"
"  const p=document.getElementById('pwd').value;"
"  if(!s) return alert('Enter SSID');"
"  if(s === curSsid) return alert('Already connected to ' + s + '!');"
"  const btn=event.target; btn.innerText='CONNECTING...'; btn.style.background='#94a3b8';"
"  fetch('/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(s)+'&pass='+encodeURIComponent(p)})"
"  .then(()=>alert('Settings saved! You will get internet access shortly.'))"
"  .finally(()=>{btn.innerText='CONNECT'; btn.style.background='#3b82f6'; setTimeout(init, 3000);});"
"}"
"function loadSettings(){"
"  fetch('/api/appass').then(r=>r.json()).then(d=>{"
"    document.getElementById('current-pass').value = d.password || 'Not set';"
"  });"
"}"
"function changePass(){"
"  const pass = document.getElementById('new-pass').value;"
"  if(pass.length < 8) return alert('Password must be at least 8 characters');"
"  const btn=event.target; btn.innerText='CHANGING...'; btn.style.background='#94a3b8';"
"  fetch('/setpass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'pass='+encodeURIComponent(pass)})"
"  .then(r=>{"
"    if(r.ok){"
"      document.getElementById('settings-msg').innerHTML='<div class=\"info-box\">Password changed! You may need to reconnect.</div>';"
"      document.getElementById('current-pass').value = pass;"
"      document.getElementById('new-pass').value = '';"
"    } else {"
"      document.getElementById('settings-msg').innerHTML='<div class=\"info-box warn\">Failed to change password.</div>';"
"    }"
"  })"
"  .finally(()=>{btn.innerText='CHANGE PASSWORD'; btn.style.background='#3b82f6';});"
"}"
"function resetAP(){"
"  if(!confirm('Reset the AP password to a new random value? You will need to reconnect.')) return;"
"  fetch('/resetpass',{method:'POST'}).then(r=>{"
"    if(r.ok){"
"      alert('AP password reset. The page will reload.');"
"      location.reload();"
"    } else {"
"      alert('Failed to reset password.');"
"    }"
"  });"
"}"
"window.onload=init;"
"</script></body></html>";

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html_page, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t status_get_handler(httpd_req_t *req)
{
    /* Zeroed so the link fields below are well defined when the station is down. */
    wifi_ap_record_t ap_info = {0};
    cJSON *root = cJSON_CreateObject();

    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        cJSON_AddStringToObject(root, "status", "connected");
        cJSON_AddStringToObject(root, "ssid", (char *)ap_info.ssid);
    } else {
        cJSON_AddStringToObject(root, "status", "disconnected");
        cJSON_AddStringToObject(root, "ssid", "");
    }
    cJSON_AddStringToObject(root, "doh", doh_relay_mode());
    cJSON_AddStringToObject(root, "mdns", s_mdns_host);

    /* Link health: a repeater's throughput is bounded by the weaker of its two
     * radio links, so these belong next to the connection state. */
    int rssi = 0;
    if (esp_wifi_sta_get_rssi(&rssi) == ESP_OK) {
        cJSON_AddNumberToObject(root, "rssi", rssi);
    }
    cJSON_AddNumberToObject(root, "ch", ap_info.primary);
    cJSON_AddNumberToObject(root, "wifi_mode", ap_info.phy_11n ? 4 : (ap_info.phy_11g ? 2 : 1));

    wifi_phy_mode_t phymode;
    if (esp_wifi_sta_get_negotiated_phymode(&phymode) == ESP_OK) {
        cJSON_AddNumberToObject(root, "phymode", (int)phymode);
    }

    /* Radio tuning, with the driver's original values alongside the active
     * ones so a change can be told apart from a no-op. */
    wifi_country_t ctry = {0};
    char cc[4];
    if (esp_wifi_get_country(&ctry) == ESP_OK) {
        country_cc(&ctry, cc);
        cJSON_AddStringToObject(root, "country", cc);
        cJSON_AddNumberToObject(root, "ch_min", ctry.schan);
        cJSON_AddNumberToObject(root, "ch_max", ctry.schan + ctry.nchan - 1);
        cJSON_AddNumberToObject(root, "ch_policy", (int)ctry.policy);
    }
    if (s_country_at_boot_valid) {
        country_cc(&s_country_at_boot, cc);
        cJSON_AddStringToObject(root, "country_at_boot", cc);
        cJSON_AddNumberToObject(root, "ch_min_at_boot", s_country_at_boot.schan);
        cJSON_AddNumberToObject(root, "ch_max_at_boot",
                                s_country_at_boot.schan + s_country_at_boot.nchan - 1);
    }
    cJSON_AddNumberToObject(root, "txpower_dbm", s_txpower_qdbm * 0.25);
    cJSON_AddStringToObject(root, "bw", s_bw_ht20 ? "HT20" : "HT40");

    cJSON_AddNumberToObject(root, "heap", esp_get_free_heap_size());
    cJSON_AddNumberToObject(root, "heap_int", esp_get_free_internal_heap_size());
    cJSON_AddNumberToObject(root, "heap_min", esp_get_minimum_free_heap_size());

    doh_stats_t st;
    doh_relay_get_stats(&st);
    cJSON_AddNumberToObject(root, "q", st.queries);
    cJSON_AddNumberToObject(root, "q_cached", st.cached);
    cJSON_AddNumberToObject(root, "q_newconn", st.new_conns);
    cJSON_AddNumberToObject(root, "q_pooled", st.pooled);
    cJSON_AddNumberToObject(root, "q_fallback", st.fallback);
    cJSON_AddNumberToObject(root, "q_servfail", st.servfail);
    cJSON_AddNumberToObject(root, "q_drops", st.drops);
    cJSON_AddNumberToObject(root, "q_dot", st.dot);
    cJSON_AddNumberToObject(root, "q_plain_rule", st.plain_rule);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t scan_get_handler(httpd_req_t *req)
{
    wifi_scan_config_t scan_conf = { .show_hidden = false };
    esp_wifi_scan_start(&scan_conf, true);

    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);
    wifi_ap_record_t *ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
    if (ap_list == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    esp_wifi_scan_get_ap_records(&ap_count, ap_list);

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < ap_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", (char *)ap_list[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", ap_list[i].rssi);
        cJSON_AddBoolToObject(item, "sec", ap_list[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(root, item);
    }
    free(ap_list);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

/* Bounded: writes at most dst_sz-1 characters plus a terminator. */
static void url_decode(char *dst, size_t dst_sz, const char *src)
{
    size_t di = 0;
    while (*src != '\0' && di + 1 < dst_sz) {
        if (src[0] == '%' && src[1] != '\0' && src[2] != '\0' &&
                isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char a = src[1];
            char b = src[2];
            a = (a >= 'a') ? (char)(a - 'a' + 10) : (a >= 'A') ? (char)(a - 'A' + 10) : (char)(a - '0');
            b = (b >= 'a') ? (char)(b - 'a' + 10) : (b >= 'A') ? (char)(b - 'A' + 10) : (char)(b - '0');
            dst[di++] = (char)(16 * a + b);
            src += 3;
        } else if (*src == '+') {
            dst[di++] = ' ';
            src++;
        } else {
            dst[di++] = *src++;
        }
    }
    dst[di] = '\0';
}

/*
 * The request body must hold the SSID plus a password of up to 63 characters,
 * each percent-encoded (3 bytes per character). A 128-byte buffer silently
 * truncated long credentials.
 */
static esp_err_t connect_post_handler(httpd_req_t *req)
{
    char buf[512];
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_ssid[128] = {0};
    char raw_pass[192] = {0};
    if (httpd_query_key_value(buf, "ssid", raw_ssid, sizeof(raw_ssid)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
        return ESP_FAIL;
    }
    httpd_query_key_value(buf, "pass", raw_pass, sizeof(raw_pass));

    char ssid[sizeof(sta_ssid)] = {0};
    char pass[sizeof(sta_password)] = {0};
    url_decode(ssid, sizeof(ssid), raw_ssid);
    url_decode(pass, sizeof(pass), raw_pass);
    if (ssid[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty ssid");
        return ESP_FAIL;
    }

    strncpy(sta_ssid, ssid, sizeof(sta_ssid) - 1);
    sta_ssid[sizeof(sta_ssid) - 1] = '\0';
    strncpy(sta_password, pass, sizeof(sta_password) - 1);
    sta_password[sizeof(sta_password) - 1] = '\0';
    save_wifi_credentials(sta_ssid, sta_password);

    ESP_LOGI(TAG_MAIN, "user selected upstream network '%s'", sta_ssid);
    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(200));

    /* Let the reconnect task own connecting, so there is a single code path. */
    if (apply_sta_config() != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "could not apply the station config");
        return ESP_OK;
    }
    esp_wifi_disconnect();
    s_sta_should_connect = true;
    xEventGroupSetBits(s_wifi_eg, STA_NEED_CONNECT_BIT | STA_BACKOFF_RESET_BIT);
    return ESP_OK;
}

/* Parse "aa:bb:cc:dd:ee:ff" (also accepting '-' separators). */
static bool parse_mac(const char *s, uint8_t out[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6 &&
            sscanf(s, "%x-%x-%x-%x-%x-%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xFF) {
            return false;
        }
        out[i] = (uint8_t)v[i];
    }
    return true;
}

static esp_err_t leases_get_handler(httpd_req_t *req)
{
    static_lease_t list[STATIC_LEASE_MAX];
    int n = static_leases_list(list, STATIC_LEASE_MAX);

    uint32_t pf = 0, pl = 0;
    bool have_pool = (ap_dhcp_pool_bounds(&pf, &pl) == ESP_OK);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "impl", ap_dhcp_impl());
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char mac[18], ip[16];
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(list[i].mac));
        esp_ip4_addr_t a = { .addr = list[i].ip };
        snprintf(ip, sizeof(ip), IPSTR, IP2STR(&a));
        cJSON_AddStringToObject(o, "mac", mac);
        cJSON_AddStringToObject(o, "ip", ip);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "leases", arr);
    cJSON_AddBoolToObject(root, "pool_known", have_pool);
    if (have_pool) {
        /* Shown so the user can see which addresses are eligible: anything the
         * allocator can also hand out is rejected. */
        char f[16], l[16];
        esp_ip4_addr_t fa = { .addr = pf }, la = { .addr = pl };
        snprintf(f, sizeof(f), IPSTR, IP2STR(&fa));
        snprintf(l, sizeof(l), IPSTR, IP2STR(&la));
        cJSON_AddStringToObject(root, "pool_first", f);
        cJSON_AddStringToObject(root, "pool_last", l);
    }

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t add_lease_post_handler(httpd_req_t *req)
{
    char buf[192] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_mac[64] = {0}, raw_ip[64] = {0};
    if (httpd_query_key_value(buf, "mac", raw_mac, sizeof(raw_mac)) != ESP_OK ||
            httpd_query_key_value(buf, "ip", raw_ip, sizeof(raw_ip)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac and ip required");
        return ESP_FAIL;
    }

    char mac_s[32] = {0}, ip_s[32] = {0};
    url_decode(mac_s, sizeof(mac_s), raw_mac);
    url_decode(ip_s, sizeof(ip_s), raw_ip);

    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC (use aa:bb:cc:dd:ee:ff)");
        return ESP_FAIL;
    }
    esp_ip4_addr_t ip;
    if (esp_netif_str_to_ip4(ip_s, &ip) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad IPv4 address");
        return ESP_FAIL;
    }

    esp_netif_ip_info_t ap;
    if (esp_netif_get_ip_info(ap_netif, &ap) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* Without pool bounds the overlap check cannot be made; refuse rather than
     * risk an address the allocator could also hand out. */
    uint32_t pf = 0, pl = 0;
    if (ap_dhcp_pool_bounds(&pf, &pl) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "pool bounds unknown; cannot validate safely");
        return ESP_FAIL;
    }

    esp_err_t err = static_leases_add(mac, ip.addr, ap.ip.addr, ap.netmask.addr, pf, pl);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "rejected: outside subnet, or inside the dynamic pool");
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t del_lease_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_mac[64] = {0};
    if (httpd_query_key_value(buf, "mac", raw_mac, sizeof(raw_mac)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    char mac_s[32] = {0};
    url_decode(mac_s, sizeof(mac_s), raw_mac);

    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }
    if (static_leases_remove(mac) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such lease");
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static const char *mode_name(uint8_t mode)
{
    return (mode == DNS_MODE_DOT) ? "dot" : (mode == DNS_MODE_PLAIN ? "dns" : "doh");
}

static esp_err_t hostname_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "hostname", s_mdns_host);
    char url[64];
    snprintf(url, sizeof(url), "http://%s.local/", s_mdns_host);
    cJSON_AddStringToObject(root, "url", url);
    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_hostname_post_handler(httpd_req_t *req)
{
    char buf[96] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw[64] = {0};
    if (httpd_query_key_value(buf, "hostname", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "hostname required");
        return ESP_FAIL;
    }
    /* Larger than the 32-char limit on purpose: url_decode() is bounded, so a
     * too-long name would otherwise be silently truncated to something valid
     * and accepted, instead of being rejected as the user's input deserves. */
    char name[64] = {0};
    url_decode(name, sizeof(name), raw);

    if (!valid_hostname(name)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "use letters, digits and hyphens only (not leading/trailing), up to 32 chars");
        return ESP_FAIL;
    }

    strncpy(s_mdns_host, name, sizeof(s_mdns_host) - 1);
    s_mdns_host[sizeof(s_mdns_host) - 1] = '\0';
    save_mdns_host();

    /* Apply live: mdns_hostname_set() announces the change, so no reboot. */
    esp_err_t err = mdns_hostname_set(s_mdns_host);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "mdns_hostname_set failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "could not apply");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG_MAIN, "mDNS name is now http://%s.local/", s_mdns_host);
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t dnsrules_get_handler(httpd_req_t *req)
{
    dns_rule_t list[DNS_RULE_MAX];
    int n = dns_rules_list(list, DNS_RULE_MAX);

    cJSON *root = cJSON_CreateObject();
    char def[DOH_URL_MAX];
    doh_relay_get_url(def, sizeof(def));
    cJSON_AddStringToObject(root, "default_url", def);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char mac[18];
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(list[i].mac));
        cJSON_AddStringToObject(o, "mac", mac);
        cJSON_AddStringToObject(o, "mode", mode_name(list[i].mode));
        cJSON_AddStringToObject(o, "addr", list[i].addr);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "rules", arr);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_dnsrule_post_handler(httpd_req_t *req)
{
    char buf[384] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_mac[64] = {0}, raw_mode[16] = {0}, raw_addr[192] = {0};
    if (httpd_query_key_value(buf, "mac", raw_mac, sizeof(raw_mac)) != ESP_OK ||
            httpd_query_key_value(buf, "mode", raw_mode, sizeof(raw_mode)) != ESP_OK ||
            httpd_query_key_value(buf, "addr", raw_addr, sizeof(raw_addr)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac, mode and addr required");
        return ESP_FAIL;
    }

    char mac_s[32] = {0}, mode_s[16] = {0}, addr_s[DNS_RULE_ADDR_MAX] = {0};
    url_decode(mac_s, sizeof(mac_s), raw_mac);
    url_decode(mode_s, sizeof(mode_s), raw_mode);
    url_decode(addr_s, sizeof(addr_s), raw_addr);

    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC (use aa:bb:cc:dd:ee:ff)");
        return ESP_FAIL;
    }
    uint8_t mode;
    if (strcasecmp(mode_s, "doh") == 0) {
        mode = DNS_MODE_DOH;
    } else if (strcasecmp(mode_s, "dot") == 0) {
        mode = DNS_MODE_DOT;
    } else if (strcasecmp(mode_s, "dns") == 0) {
        mode = DNS_MODE_PLAIN;
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mode must be doh, dot or dns");
        return ESP_FAIL;
    }

    esp_err_t err = dns_rules_set(mac, mode, addr_s);
    if (err == ESP_ERR_INVALID_ARG) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "bad address: DoH needs an https:// URL; DoT/DNS need an IPv4 literal (IP or IP:port)");
        return ESP_FAIL;
    }
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "too many rules");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t del_dnsrule_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_mac[64] = {0};
    if (httpd_query_key_value(buf, "mac", raw_mac, sizeof(raw_mac)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    char mac_s[32] = {0};
    url_decode(mac_s, sizeof(mac_s), raw_mac);
    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }
    if (dns_rules_remove(mac) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such rule");
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/*
 * Run a real query through each configured resolver and report the outcome.
 *
 * This is the only way to exercise DoT and the DoH/plain paths for a per-device
 * rule without a client on the AP: it uses the same resolver code the relay
 * serves clients with, against real servers, so a broken framing or TLS setup
 * shows up here instead of silently degrading every lookup.
 */
static esp_err_t dnstest_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();

    char def[DOH_URL_MAX];
    doh_relay_get_url(def, sizeof(def));
    char result[128];
    doh_relay_probe(DNS_MODE_DOH, def, "example.com", result, sizeof(result));
    cJSON *d = cJSON_CreateObject();
    cJSON_AddStringToObject(d, "addr", def);
    cJSON_AddStringToObject(d, "mode", "doh");
    cJSON_AddStringToObject(d, "result", result);
    cJSON_AddItemToObject(root, "default", d);

    dns_rule_t list[DNS_RULE_MAX];
    int n = dns_rules_list(list, DNS_RULE_MAX);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(list[i].mac));
        doh_relay_probe(list[i].mode, list[i].addr, "example.com", result, sizeof(result));
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "mac", mac);
        cJSON_AddStringToObject(o, "mode", mode_name(list[i].mode));
        cJSON_AddStringToObject(o, "addr", list[i].addr);
        cJSON_AddStringToObject(o, "result", result);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "rules", arr);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t portmaps_get_handler(httpd_req_t *req)
{
    portmap_entry_t list[PORTMAP_MAX];
    int n = portmap_list(list, PORTMAP_MAX);

    /* The external address is the station's, so show it: it is also what tells
     * the user the mapping is only reachable from the upstream LAN. */
    esp_netif_ip_info_t sta = {0};
    esp_netif_get_ip_info(sta_netif, &sta);

    cJSON *root = cJSON_CreateObject();
    char buf[20];
    snprintf(buf, sizeof(buf), IPSTR, IP2STR(&sta.ip));
    cJSON_AddStringToObject(root, "external", buf);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        esp_ip4_addr_t d = { .addr = list[i].daddr };
        cJSON_AddStringToObject(o, "proto", list[i].proto == 6 ? "tcp" : "udp");
        cJSON_AddNumberToObject(o, "mport", list[i].mport);
        snprintf(buf, sizeof(buf), IPSTR, IP2STR(&d));
        cJSON_AddStringToObject(o, "daddr", buf);
        cJSON_AddNumberToObject(o, "dport", list[i].dport);
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "rules", arr);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t add_portmap_post_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_proto[16] = {0}, raw_mport[16] = {0}, raw_addr[64] = {0}, raw_dport[16] = {0};
    if (httpd_query_key_value(buf, "proto", raw_proto, sizeof(raw_proto)) != ESP_OK ||
            httpd_query_key_value(buf, "mport", raw_mport, sizeof(raw_mport)) != ESP_OK ||
            httpd_query_key_value(buf, "daddr", raw_addr, sizeof(raw_addr)) != ESP_OK ||
            httpd_query_key_value(buf, "dport", raw_dport, sizeof(raw_dport)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "proto, mport, daddr and dport required");
        return ESP_FAIL;
    }

    char proto_s[16] = {0}, addr_s[64] = {0};
    url_decode(proto_s, sizeof(proto_s), raw_proto);
    url_decode(addr_s, sizeof(addr_s), raw_addr);

    uint8_t proto;
    if (strcasecmp(proto_s, "tcp") == 0) {
        proto = 6;
    } else if (strcasecmp(proto_s, "udp") == 0) {
        proto = 17;
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "proto must be tcp or udp");
        return ESP_FAIL;
    }

    long mp = strtol(raw_mport, NULL, 10);
    long dp = strtol(raw_dport, NULL, 10);
    if (mp < 1 || mp > 65535 || dp < 1 || dp > 65535) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ports must be 1-65535");
        return ESP_FAIL;
    }

    esp_ip4_addr_t daddr;
    if (esp_netif_str_to_ip4(addr_s, &daddr) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad target IPv4 address");
        return ESP_FAIL;
    }

    esp_netif_ip_info_t ap = {0};
    if (esp_netif_get_ip_info(ap_netif, &ap) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    esp_err_t err = portmap_add(proto, (uint16_t)mp, daddr.addr, (uint16_t)dp,
                                ap.ip.addr, ap.netmask.addr);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "rejected: target must be a client on the AP subnet");
        return ESP_FAIL;
    }

    /* Push it live with the current station address. */
    esp_netif_ip_info_t sta = {0};
    if (esp_netif_get_ip_info(sta_netif, &sta) == ESP_OK && sta.ip.addr != 0) {
        portmap_apply_all(sta.ip.addr);
    }

    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t del_portmap_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_proto[16] = {0}, raw_mport[16] = {0};
    if (httpd_query_key_value(buf, "proto", raw_proto, sizeof(raw_proto)) != ESP_OK ||
            httpd_query_key_value(buf, "mport", raw_mport, sizeof(raw_mport)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "proto and mport required");
        return ESP_FAIL;
    }
    char proto_s[16] = {0};
    url_decode(proto_s, sizeof(proto_s), raw_proto);
    uint8_t proto = (strcasecmp(proto_s, "udp") == 0) ? 17 : 6;
    long mp = strtol(raw_mport, NULL, 10);
    if (mp < 1 || mp > 65535) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad port");
        return ESP_FAIL;
    }
    if (portmap_remove(proto, (uint16_t)mp) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such rule");
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t radio_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "bw", s_bw_ht20 ? "HT20" : "HT40");
    cJSON_AddNumberToObject(root, "txpower_dbm", s_txpower_qdbm * 0.25);

    wifi_country_t ctry = {0};
    char cc[4];
    if (esp_wifi_get_country(&ctry) == ESP_OK) {
        country_cc(&ctry, cc);
        cJSON_AddStringToObject(root, "country", cc);
        cJSON_AddNumberToObject(root, "ch_min", ctry.schan);
        cJSON_AddNumberToObject(root, "ch_max", ctry.schan + ctry.nchan - 1);
    }

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

/* Bandwidth only. HT20 uses half the airtime of HT40 and needs less SNR margin,
 * which can matter more than peak rate for a repeater serving distant clients;
 * HT40 is faster when the spectrum is clean. Which wins here is
 * environment-dependent, so it is a setting rather than a hardcoded choice. */
static esp_err_t set_radio_post_handler(httpd_req_t *req)
{
    char buf[64] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char bw[8] = {0};
    if (httpd_query_key_value(buf, "bw", bw, sizeof(bw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing bw");
        return ESP_FAIL;
    }

    bool want_ht20;
    if (strcmp(bw, "20") == 0) {
        want_ht20 = true;
    } else if (strcmp(bw, "40") == 0) {
        want_ht20 = false;
    } else {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bw must be 20 or 40");
        return ESP_FAIL;
    }

    if (want_ht20 == s_bw_ht20) {
        httpd_resp_sendstr(req, "OK");   /* already there, nothing to do */
        return ESP_OK;
    }

    s_bw_ht20 = want_ht20;
    save_radio_settings();

    /* Answer before touching the radio: re-applying bandwidth on the station
     * interface forces it to renegotiate and drops the link, which tears down
     * this very HTTP connection. Sending the response first is what keeps a
     * successful change from being reported to the browser as a failure. */
    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(200));

    apply_bandwidth();
    ESP_LOGI(TAG_MAIN, "bandwidth changed to %s", s_bw_ht20 ? "HT20" : "HT40");
    return ESP_OK;
}

static esp_err_t clients_get_handler(httpd_req_t *req)
{
    client_info_t list[CLIENTS_MAX];
    int n = clients_snapshot(list, CLIENTS_MAX);

    cJSON *arr = cJSON_CreateArray();
    int64_t now_us = esp_timer_get_time();
    for (int i = 0; i < n; i++) {
        cJSON *o = cJSON_CreateObject();
        char mac[18];
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(list[i].mac));
        cJSON_AddStringToObject(o, "mac", mac);
        if (list[i].ip_valid) {
            char ip[16];
            snprintf(ip, sizeof(ip), IPSTR, IP2STR(&list[i].ip));
            cJSON_AddStringToObject(o, "ip", ip);
        } else {
            cJSON_AddStringToObject(o, "ip", "");
        }
        cJSON_AddStringToObject(o, "host", list[i].hostname);
        cJSON_AddNumberToObject(o, "rssi", list[i].rssi);
        cJSON_AddNumberToObject(o, "phy", list[i].phy);
        cJSON_AddNumberToObject(o, "uptime",
                                list[i].joined_us ? (now_us - list[i].joined_us) / 1000000 : 0);
        cJSON_AddItemToArray(arr, o);
    }

    const char *json = cJSON_PrintUnformatted(arr);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(arr);
    return ESP_OK;
}

static esp_err_t doh_url_get_handler(httpd_req_t *req)
{
    char current[DOH_URL_MAX];
    doh_relay_get_url(current, sizeof(current));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "url", current);
    cJSON_AddStringToObject(root, "mode", doh_relay_mode());
    cJSON_AddStringToObject(root, "default", DOH_DEFAULT_URL);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_doh_url_post_handler(httpd_req_t *req)
{
    char buf[384] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_url[320] = {0};
    if (httpd_query_key_value(buf, "url", raw_url, sizeof(raw_url)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing url");
        return ESP_FAIL;
    }

    char url[DOH_URL_MAX] = {0};
    url_decode(url, sizeof(url), raw_url);
    if (strlen(url) < 8) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "url too short");
        return ESP_FAIL;
    }

    /* Plain http:// would defeat the point of the module. */
    if (doh_relay_set_url(url) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "must be an https:// URL");
        return ESP_FAIL;
    }

    strncpy(doh_url, url, sizeof(doh_url) - 1);
    doh_url[sizeof(doh_url) - 1] = '\0';
    save_doh_url(doh_url);

    /* No WiFi restart needed: only the relay's upstream changes. */
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t ap_pass_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "password", ap_password);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));

    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_pass_post_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_pass[192] = {0};
    if (httpd_query_key_value(buf, "pass", raw_pass, sizeof(raw_pass)) != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char new_pass[sizeof(ap_password)] = {0};
    url_decode(new_pass, sizeof(new_pass), raw_pass);
    if (strlen(new_pass) < 8) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "password too short");
        return ESP_FAIL;
    }

    strncpy(ap_password, new_pass, sizeof(ap_password) - 1);
    ap_password[sizeof(ap_password) - 1] = '\0';

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ap_pass", ap_password);
        nvs_commit(h);
        nvs_close(h);
    }

    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(200));

    apply_ap_config();
    /* Restarting WiFi also drops the upstream link, so let the reconnect task
     * come back immediately rather than after a long backoff. */
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_wifi_start();
    xEventGroupSetBits(s_wifi_eg, STA_BACKOFF_RESET_BIT | STA_NEED_CONNECT_BIT);

    ESP_LOGI(TAG_AP, "AP password changed");
    return ESP_OK;
}

static esp_err_t reset_pass_handler(httpd_req_t *req)
{
    generate_ap_password();

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ap_pass", ap_password);
        nvs_commit(h);
        nvs_close(h);
    }

    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(200));

    apply_ap_config();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_wifi_start();
    xEventGroupSetBits(s_wifi_eg, STA_BACKOFF_RESET_BIT | STA_NEED_CONNECT_BIT);

    ESP_LOGI(TAG_AP, "AP password reset to a new random value: %s", ap_password);
    return ESP_OK;
}

static void start_http_server(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 36;
    cfg.stack_size = 6144;
    cfg.lru_purge_enable = true;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "could not start the web server");
        return;
    }

    const httpd_uri_t uris[] = {
        { .uri = "/",           .method = HTTP_GET,  .handler = root_get_handler },
        { .uri = "/status",     .method = HTTP_GET,  .handler = status_get_handler },
        { .uri = "/scan",       .method = HTTP_GET,  .handler = scan_get_handler },
        { .uri = "/connect",    .method = HTTP_POST, .handler = connect_post_handler },
        { .uri = "/api/appass", .method = HTTP_GET,  .handler = ap_pass_get_handler },
        { .uri = "/setpass",    .method = HTTP_POST, .handler = set_pass_post_handler },
        { .uri = "/resetpass",  .method = HTTP_POST, .handler = reset_pass_handler },
        { .uri = "/api/dohurl", .method = HTTP_GET,  .handler = doh_url_get_handler },
        { .uri = "/setdohurl",  .method = HTTP_POST, .handler = set_doh_url_post_handler },
        { .uri = "/api/clients", .method = HTTP_GET, .handler = clients_get_handler },
        { .uri = "/api/radio",   .method = HTTP_GET,  .handler = radio_get_handler },
        { .uri = "/setradio",    .method = HTTP_POST, .handler = set_radio_post_handler },
        { .uri = "/api/leases",  .method = HTTP_GET,  .handler = leases_get_handler },
        { .uri = "/lease/add",   .method = HTTP_POST, .handler = add_lease_post_handler },
        { .uri = "/lease/del",   .method = HTTP_POST, .handler = del_lease_post_handler },
        { .uri = "/api/dnsrules", .method = HTTP_GET,  .handler = dnsrules_get_handler },
        { .uri = "/api/hostname", .method = HTTP_GET,  .handler = hostname_get_handler },
        { .uri = "/sethostname",  .method = HTTP_POST, .handler = set_hostname_post_handler },
        { .uri = "/dnsrule/set",  .method = HTTP_POST, .handler = set_dnsrule_post_handler },
        { .uri = "/dnsrule/del",  .method = HTTP_POST, .handler = del_dnsrule_post_handler },
        { .uri = "/api/dnstest",  .method = HTTP_GET,  .handler = dnstest_get_handler },
        { .uri = "/api/portmaps", .method = HTTP_GET,  .handler = portmaps_get_handler },
        { .uri = "/portmap/add",  .method = HTTP_POST, .handler = add_portmap_post_handler },
        { .uri = "/portmap/del",  .method = HTTP_POST, .handler = del_portmap_post_handler },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(server, &uris[i]);
    }
    ESP_LOGI(TAG_MAIN, "web interface ready on http://192.168.4.1");
}

/* ======================= main ======================= */

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* The RGB LED keeps the colour the previous firmware latched into it. */
    led_off_silence_boot();

    load_wifi_credentials();
    load_doh_url();
    load_mdns_host();
    load_radio_settings();

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);

    bool password_generated = false;
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        size_t len = sizeof(ap_password);
        if (nvs_get_str(h, "ap_pass", ap_password, &len) != ESP_OK) {
            generate_ap_password();
            nvs_set_str(h, "ap_pass", ap_password);
            nvs_commit(h);
            password_generated = true;
        }
        nvs_close(h);
    }
    snprintf(ap_ssid_full, sizeof(ap_ssid_full), "%s-%02X%02X",
             AP_SSID_PREFIX, mac[4], mac[5]);

    ESP_LOGI(TAG_MAIN, "==============================");
    ESP_LOGI(TAG_MAIN, "AP SSID:     %s", ap_ssid_full);
    ESP_LOGI(TAG_MAIN, "AP Password: %s", ap_password);
    if (password_generated) {
        ESP_LOGW(TAG_MAIN, ">>> NEW RANDOM PASSWORD GENERATED <<<");
    }
    ESP_LOGI(TAG_MAIN, "web config:  http://192.168.4.1");
    ESP_LOGI(TAG_MAIN, "==============================");

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    clients_init();
    static_leases_init();
    portmap_init();
    dns_rules_init();

    s_wifi_eg = xEventGroupCreate();
    if (s_wifi_eg == NULL) {
        ESP_LOGE(TAG_MAIN, "cannot create the event group");
        return;
    }

    ap_netif = esp_netif_create_default_wifi_ap();
    sta_netif = esp_netif_create_default_wifi_sta();
    /* Our own traffic (DoH, SNTP) must leave through the upstream link. */
    esp_netif_set_default_netif(sta_netif);

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                    IP_EVENT_ASSIGNED_IP_TO_CLIENT, wifi_event_handler, NULL, NULL));
    /* Only fires when the vendored DHCP server is in use; harmless otherwise. */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(AP_DHCP_EVENT,
                    ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    /* What was stored before this run overrode it. Note this reflects a value
     * persisted by any earlier run, not necessarily the factory profile. */
    s_country_at_boot_valid = (esp_wifi_get_country(&s_country_at_boot) == ESP_OK);
    if (s_country_at_boot_valid) {
        ESP_LOGI(TAG_MAIN, "country as found at boot='%.3s' ch=%u-%u policy=%d",
                 s_country_at_boot.cc, s_country_at_boot.schan,
                 (unsigned)(s_country_at_boot.schan + s_country_at_boot.nchan - 1),
                 (int)s_country_at_boot.policy);
    }

    /* ieee80211d disabled on purpose: with it enabled the station re-adopts
     * whatever country the upstream AP advertises, which is the behaviour we
     * are replacing. */
    esp_err_t cerr = esp_wifi_set_country_code("CN", false);
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG_MAIN, "country code not set: %s", esp_err_to_name(cerr));
    }

    ESP_ERROR_CHECK(apply_ap_config());
    if (sta_ssid[0] != '\0') {
        ESP_ERROR_CHECK(apply_sta_config());
    }

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG_MAIN, "wifi started, AP '%s'", ap_ssid_full);

    /* 80 * 0.25 dBm = 20 dBm, the 2.4 GHz ceiling for CN. The world-safe default
     * can be lower. Only settable once the driver has started. */
    esp_err_t perr = esp_wifi_set_max_tx_power(80);
    int8_t eff_power = 0;
    if (esp_wifi_get_max_tx_power(&eff_power) == ESP_OK) {
        s_txpower_qdbm = eff_power;
    }
    ESP_LOGI(TAG_MAIN, "tx power %d (%.2f dBm), set rc=%s",
             s_txpower_qdbm, s_txpower_qdbm * 0.25f, esp_err_to_name(perr));
    apply_bandwidth();

    /* The default modem-sleep policy parks the radio between DTIM beacons, which
     * adds a wake-up delay to every round trip. Measured effect: a TLS
     * handshake to the DoH resolver took 2.76 s versus 0.10 s from a laptop on
     * the same network. This board is mains-powered, so there is nothing to
     * gain from sleeping -- and disabling it also lowers forwarding latency for
     * every client behind the repeater. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG_MAIN, "wifi power save disabled");

    ESP_ERROR_CHECK(ap_dhcp_start(ap_netif));
    ESP_ERROR_CHECK(doh_relay_start(ap_netif, sta_netif, doh_url));

    if (xTaskCreate(sta_reconnect_task, "sta_reconnect", 4096, NULL, 5,
                    &s_reconnect_task) != pdPASS) {
        ESP_LOGE(TAG_MAIN, "cannot create the reconnect task");
        return;
    }
    if (sta_ssid[0] != '\0') {
        s_sta_should_connect = true;
        xEventGroupSetBits(s_wifi_eg, STA_NEED_CONNECT_BIT);
    }

    start_sntp();
    start_http_server();
    start_mdns();
}
