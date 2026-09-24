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
#include "doh_relay.h"
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
"  if(tab==='settings'){ loadSettings(); loadDoh(); loadRadio(); }"
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
    cfg.max_uri_handlers = 20;
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
}
