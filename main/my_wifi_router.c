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
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mdns.h"
#include "esp_tls_crypto.h"   /* esp_crypto_base64_encode, for HTTP Basic auth */
#include "ap_acl.h"
#include "web_auth.h"
#include "devices.h"
#include "esp_event.h"
#include "esp_sntp.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_http_server.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "cJSON.h"

#include "ap_dhcp.h"
#include "clients.h"
#include "fw_update.h"
#include "dns_rules.h"
#include "doh_relay.h"
#include "portmap.h"
#include "static_leases.h"
#include "led_off.h"

/* Default AP name; the live value is stored in NVS and editable from the
 * settings page, so a rename does not need a reflash. */
#define AP_SSID_PREFIX    "EMBEDWRT"
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
static char ap_ssid_full[33] = {0};   /* the live AP name, from NVS or the default */
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

/*
 * A registered route: the httpd entry plus the real handler. Every route is
 * registered through the table below with the auth trampoline in front, so a new
 * endpoint cannot accidentally be added without authentication.
 */
typedef struct {
    httpd_uri_t uri;                       /* handler/user_ctx filled in at registration */
    esp_err_t (*real)(httpd_req_t *);
    bool admin_only;                       /* guests get 401 instead of the handler */
    /* Also acceptable with the developer token instead of a session. Only the
     * firmware-update routes set this, so a leaked token cannot do anything
     * beyond flashing. Trailing and almost always omitted, so C zero-fills it
     * and only the routes that want it have to say so. */
    bool token_ok;
} route_t;

/*
 * Which device is this request coming from, and what may it touch?
 *
 * Admins bypass all of this. A guest is identified solely by its source address,
 * so a caller outside the AP subnet has no identity and owns nothing - the
 * correct outcome, not a gap.
 */
static bool caller_mac(httpd_req_t *req, uint8_t mac_out[6])
{
    uint32_t ip = 0;
    if (!web_auth_client_ip(req, &ip)) {
        return false;
    }
    return clients_mac_for_ip(ip, mac_out);
}

/* Admins may touch anything; a guest only what devices.c says it may. */
static bool caller_may_touch(httpd_req_t *req, const uint8_t target[6])
{
    if (web_auth_role_of(req) == WEB_ROLE_ADMIN) {
        return true;
    }
    uint8_t me[6] = {0};
    return caller_mac(req, me) && devices_visible(target, me);
}

/*
 * Developer mode: does this request carry the token?
 *
 * Called only for routes that opted in, so it does not need to know which
 * endpoints matter. A missing header is the ordinary case and must not be
 * logged as a failure, or a guest hitting an OTA route would fill the console.
 */
static bool developer_token_authorized(httpd_req_t *req)
{
    if (!fw_dev_mode()) {
        return false;
    }
    if (httpd_req_get_hdr_value_len(req, "X-OTA-Token") != FW_DEV_TOKEN_LEN - 1) {
        return false;
    }
    char presented[FW_DEV_TOKEN_LEN];
    if (httpd_req_get_hdr_value_str(req, "X-OTA-Token", presented,
                                    sizeof(presented)) != ESP_OK) {
        return false;
    }
    if (!fw_dev_token_ok(presented)) {
        ESP_LOGW(TAG_MAIN, "developer token presented but wrong");
        return false;
    }
    ESP_LOGW(TAG_MAIN, "%s authorized by developer token", req->uri);
    return true;
}

/* ======================= route authorization ======================= */

/*
 * The per-request gate. Role resolution and the session table live in
 * web_auth.c; this only decides whether the route may run.
 *
 * Every route goes through here (registration sets it as the handler and passes
 * itself as user_ctx), so a new endpoint cannot be added without a decision
 * about who may reach it - the admin_only flag is not optional at the call site
 * because the struct initialiser would leave it false, which is the safe
 * default only if reviewed. Admin-only routes are listed explicitly below.
 */
static esp_err_t auth_trampoline(httpd_req_t *req)
{
    const route_t *r = (const route_t *)req->user_ctx;
    if (r == NULL || r->real == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /*
     * A device that loads the panel is not a dumb IoT device any more, so drop
     * its own IoT flag (configurable). This runs for every request, and only
     * ever affects the requesting device's own record - which is why it cannot
     * lock anyone out: a device always sees itself regardless of the flag, and
     * the devices it owns keep theirs.
     *
     * Clearing is a no-op unless the flag was set, so there is no NVS write on
     * the normal path.
     */
    if (devices_clear_iot_on_visit()) {
        uint8_t self[6];
        if (caller_mac(req, self)) {
            devices_clear_iot(self);
        }
    }

    if (r->admin_only && web_auth_role_of(req) != WEB_ROLE_ADMIN) {
        /*
         * Developer mode: a token in a header stands in for a session, but only
         * on the routes that opted in (the firmware-update ones) and only while
         * the mode is switched on. Reading the header is cheap and the token
         * comparison does not leak, so a wrong token costs nothing.
         */
        if (r->token_ok && developer_token_authorized(req)) {
            return r->real(req);
        }
        /* 401 rather than 403: the caller can fix this by logging in, and the
         * UI keys its login prompt off exactly this status. */
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":\"login required\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    return r->real(req);
}

/* ======================= AP name ======================= */

/*
 * The AP name is a stored setting rather than a compile-time constant, so it can
 * be changed without a reflash. Changing it restarts the radio (the same path
 * the AP password change takes), which drops every client and the upstream link
 * for a moment - unavoidable, since the SSID is broadcast in the beacon and
 * cannot be altered in place.
 */
static void load_ap_ssid(void)
{
    nvs_handle_t h;
    size_t len = sizeof(ap_ssid_full);
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_str(h, "ap_ssid", ap_ssid_full, &len) == ESP_OK && ap_ssid_full[0] != '\0') {
            nvs_close(h);
            ESP_LOGI(TAG_MAIN, "AP name from NVS: '%s'", ap_ssid_full);
            return;
        }
        nvs_close(h);
    }

    /* First boot: derive a unique default from the MAC and store it, so the
     * name the user sees is the one that is persisted. */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(ap_ssid_full, sizeof(ap_ssid_full), "%s-%02X%02X",
             AP_SSID_PREFIX, mac[4], mac[5]);

    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ap_ssid", ap_ssid_full);
        nvs_commit(h);
        nvs_close(h);
    }
}

static esp_err_t save_ap_ssid(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    esp_err_t err = nvs_set_str(h, "ap_ssid", ap_ssid_full);
    nvs_commit(h);
    nvs_close(h);
    return err;
}

/* An SSID is a byte string of 1-32 octets. Control characters are excluded
 * because they are invisible or break clients' display, and a leading/trailing
 * space is almost always a typo the user cannot see. */
static bool valid_ssid(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > 32) {
        return false;
    }
    if (s[0] == ' ' || s[n - 1] == ' ') {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F) {
            return false;
        }
    }
    return true;
}

/* ======================= AP settings ======================= */

/*
 * Hide-SSID, max clients and TX power. These live as plain variables loaded from
 * NVS rather than in a struct, matching how the AP name is handled.
 */
static bool s_ap_hidden;
static uint8_t s_ap_maxconn = 7;
static int8_t s_txpower_qdbm = 80;    /* 0.25 dBm units, so 80 = 20 dBm */

#define AP_MAXCONN_MIN 1
#define AP_MAXCONN_MAX 10          /* the driver's ceiling for a soft-AP */
#define AP_TXPOWER_MIN 8           /* 2 dBm  */
#define AP_TXPOWER_MAX 84          /* 21 dBm */

static void load_ap_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    uint8_t u = 0;
    if (nvs_get_u8(h, "ap_hidden", &u) == ESP_OK) {
        s_ap_hidden = (u != 0);
    }
    if (nvs_get_u8(h, "ap_maxconn", &u) == ESP_OK &&
            u >= AP_MAXCONN_MIN && u <= AP_MAXCONN_MAX) {
        s_ap_maxconn = u;
    }
    int8_t p = 0;
    if (nvs_get_i8(h, "ap_txpower", &p) == ESP_OK &&
            p >= AP_TXPOWER_MIN && p <= AP_TXPOWER_MAX) {
        s_txpower_qdbm = p;
    }
    nvs_close(h);
}

static esp_err_t save_ap_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_u8(h, "ap_hidden", s_ap_hidden ? 1 : 0);
    nvs_set_u8(h, "ap_maxconn", s_ap_maxconn);
    nvs_set_i8(h, "ap_txpower", s_txpower_qdbm);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
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
    c.ap.max_connection = s_ap_maxconn;
    c.ap.ssid_hidden = s_ap_hidden ? 1 : 0;
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
        /* Enforced after the fact: IDF cannot refuse an association, so a
         * disallowed station is deauthenticated the moment it appears. */
        ap_acl_kick_if_denied(e->mac);
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
        /* The updater waits for an address before it will talk to the server, so
         * it has to be told when one goes away. */
        fw_update_set_online(false);
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
        /* Releases the firmware updater, which holds off until there is an
         * address - the check is an outbound request like any other. */
        fw_update_set_online(true);
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
static char s_mdns_host[33] = "embedwrt";

static void load_mdns_host(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    size_t len = sizeof(s_mdns_host);
    if (nvs_get_str(h, "mdns_host", s_mdns_host, &len) != ESP_OK) {
        strncpy(s_mdns_host, "embedwrt", sizeof(s_mdns_host) - 1);
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
"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>EmbedWRT</title>"
"<link rel='icon' href='data:,'>"
"<style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{font-family:system-ui,-apple-system,'Noto Sans SC','Microsoft YaHei',sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:flex-start;min-height:100vh;color:#1e293b;padding:16px 0}"
".card{background:#fff;border-radius:12px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:100%;max-width:420px;overflow:hidden}"
".header{background:linear-gradient(135deg,#1e293b,#334155);padding:20px 24px;text-align:center;color:#fff;position:relative}"
".header-icon svg{width:32px;height:32px;fill:#60a5fa}"
".header h1{font-size:18px;font-weight:700;color:#f1f5f9;letter-spacing:0.5px}"
".header .subtitle{font-size:11px;color:#94a3b8;margin-top:4px}"
"#lang-btn{position:absolute;top:12px;right:12px;background:rgba(255,255,255,.12);color:#e2e8f0;border:1px solid rgba(255,255,255,.25);border-radius:6px;padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer}"
"#lang-btn:hover{background:rgba(255,255,255,.22)}"
"#auth-btn{position:absolute;top:12px;left:12px;background:rgba(255,255,255,.12);color:#e2e8f0;border:1px solid rgba(255,255,255,.25);border-radius:6px;padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer}"
"#auth-btn:hover{background:rgba(255,255,255,.22)}"
"#modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);align-items:center;justify-content:center;padding:20px;z-index:50}"
"#modal .box{background:#fff;border-radius:12px;padding:20px;width:100%;max-width:330px}"
"#modal h3{font-size:15px;margin-bottom:14px;color:#0f172a}"
"#modal .err{color:#b91c1c;font-size:12px;min-height:16px;margin-top:8px}"
"#guest-view{display:none;padding:22px}"
".tabs{display:flex;border-bottom:1px solid #e2e8f0}"
".tab{flex:1;text-align:center;padding:14px 6px;font-size:13px;font-weight:600;color:#64748b;background:#f8fafc;border:none;cursor:pointer}"
".tab.active{color:#3b82f6;background:#fff;border-bottom:2px solid #3b82f6}"
".tab-content{display:none;padding:20px}"
".tab-content.active{display:block}"
".header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}"
"h1{font-size:19px;color:#0f172a}"
"h2{font-size:14px;color:#334155;margin:22px 0 8px;padding-top:16px;border-top:1px solid #e2e8f0}"
"h2:first-of-type{margin-top:8px;padding-top:0;border-top:none}"
".refresh-btn{background:#e2e8f0;color:#475569;border:none;padding:7px 11px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer}"
".refresh-btn:hover{background:#cbd5e1}"
"#status-msg{text-align:center;font-size:13px;margin-bottom:8px;font-weight:500;padding:8px;border-radius:6px;background:#f8fafc}"
".hint{font-size:11px;color:#94a3b8;margin-bottom:10px;line-height:1.5}"
".network-list{border:1px solid #e2e8f0;border-radius:8px;margin-bottom:14px;max-height:200px;overflow-y:auto;background:#fafafa}"
".network-item{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid #e2e8f0;cursor:pointer}"
".network-item:last-child{border-bottom:none}"
".network-item:hover{background:#f1f5f9}"
".net-info{display:flex;align-items:center;gap:8px;font-size:14px;color:#334155}"
".icon{width:16px;height:16px}"
".icon.secure{fill:#94a3b8}"
".form-group{margin-bottom:12px}"
"label{display:block;font-size:12px;color:#475569;margin-bottom:5px;font-weight:500}"
"input,select{width:100%;padding:9px 11px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px;outline:none;background:#fff}"
"input:focus,select:focus{border-color:#3b82f6}"
".btn{width:100%;background:#3b82f6;color:white;border:none;padding:11px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px}"
".btn:hover{background:#2563eb}"
".btn.danger{background:#ef4444}"
".btn.danger:hover{background:#dc2626}"
".btn.small{padding:8px;font-size:12px}"
".loading{text-align:center;padding:18px;font-size:13px;color:#64748b}"
".info-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:11px;margin-bottom:12px;font-size:12px;color:#166534;line-height:1.5}"
".info-box.warn{background:#fef2f2;border-color:#fecaca;color:#991b1b}"
".row{display:flex;gap:8px}"
".row>*{flex:1}"
".footer{margin-top:22px;padding-top:14px;border-top:1px solid #e2e8f0;text-align:center;font-size:11px;color:#94a3b8;line-height:1.6}"
".footer a{color:#64748b;text-decoration:none}"
".mono{font-family:ui-monospace,Menlo,Consolas,monospace}"
".testout{font-size:11px;line-height:1.7;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}"
"</style></head><body>"
"<div class='card'>"
"  <div class='header'>"
"    <button id='lang-btn' onclick='toggleLang()'>中文</button>"
"    <button id='auth-btn' onclick='authButton()'>Log in</button>"
"    <div class='header-icon'><svg viewBox='0 0 24 24'><path d='M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z'/></svg></div>"
"    <h1 data-i18n='title'>EmbedWRT</h1>"
"    <div class='subtitle' data-i18n='subtitle'>WiFi NAT router &middot; DoH / DoT</div>"
"  </div>"
"  <div id='guest-view'>"
"    <div class='hint' id='guest-body' style='margin:0 0 14px' data-i18n='guest_body'></div>"
"    <div id='guest-ident' class='hint'></div>"
"    <div id='guest-devices'></div>"
"    <button class='btn' style='margin-top:14px' onclick='showLogin()' data-i18n='login_btn'>Log in</button>"
"  </div>"
"  <div id='admin-view'>"
"  <div class='tabs'>"
"    <button class='tab active' onclick='switchTab(\"wifi\",event)' data-i18n='tab_wifi'>WiFi</button>"
"    <button class='tab' onclick='switchTab(\"clients\",event)' data-i18n='tab_clients'>Clients</button>"
"    <button class='tab' onclick='switchTab(\"settings\",event)' data-i18n='tab_settings'>Settings</button>"
"  </div>"
""
"  <div id='tab-wifi' class='tab-content active'>"
"    <div class='header-row'><h1 data-i18n='wifi_setup'>WiFi</h1><button class='refresh-btn' onclick='scan()' data-i18n='refresh'>Refresh</button></div>"
"    <div id='status-msg'></div>"
"    <div id='dns-msg' class='hint'></div>"
"    <div class='network-list' id='list'><div class='loading' data-i18n='scanning_networks'>Scanning...</div></div>"
"    <div class='form-group'><label data-i18n='ssid_label'>Network name</label><input type='text' id='ssid' data-i18n-ph='ssid_ph' placeholder='Network name'></div>"
"    <div class='form-group'><label data-i18n='password_label'>Password</label><input type='password' id='pwd' data-i18n-ph='pass_ph' placeholder='Password'></div>"
"    <button class='btn' onclick='connect()' data-i18n='connect_btn'>CONNECT</button>"
"  </div>"
""
"  <div id='tab-clients' class='tab-content'>"
"    <div class='header-row'><h1 data-i18n='tab_clients'>Clients</h1><button class='refresh-btn' onclick='loadClients()' data-i18n='refresh'>Refresh</button></div>"
"    <div class='hint' data-i18n='clients_hint'></div>"
"    <div id='client-list'><div class='loading' data-i18n='loading'>Loading...</div></div>"
"  </div>"
""
"  <div id='tab-settings' class='tab-content'>"
"    <h1 data-i18n='tab_settings'>Settings</h1>"
""
"    <h2 data-i18n='sec_ap'>Access point</h2>"
"    <div class='form-group'><label data-i18n='ap_name'>AP name (SSID)</label><input type='text' id='ssid-name'><div class='hint' style='margin:6px 0 0' data-i18n='ap_name_hint'></div></div>"
"    <button class='btn' onclick='saveSsid()' data-i18n='save_name_btn'>SAVE NAME</button>"
"    <div class='form-group' style='margin-top:14px'><label data-i18n='cur_ap_pass'>Current password</label><input type='text' id='current-pass' readonly></div>"
"    <div class='form-group'><label data-i18n='new_ap_pass'>New password</label><input type='text' id='new-pass' data-i18n-ph='new_pass_ph' placeholder='at least 8 characters'></div>"
"    <button class='btn' onclick='changePass()' data-i18n='change_pass_btn'>CHANGE PASSWORD</button>"
"    <div style='margin-top:8px'><button class='btn danger small' onclick='resetAP()' data-i18n='reset_btn'>RESET TO RANDOM</button></div>"
""
"    <h2 data-i18n='sec_panel'>Web panel access</h2>"
"    <div id='auth-state' class='hint'></div>"
"    <div class='row form-group'><div><label data-i18n='user_label'>User</label><input type='text' id='web-user'></div></div>"
"    <div class='form-group'><label data-i18n='panel_pass'>Password</label><input type='password' id='web-pass' data-i18n-ph='panel_pass_ph' placeholder='empty = no password'></div>"
"    <button class='btn' onclick='savePanelAuth()' data-i18n='save_auth_btn'>SAVE</button>"
""
"    <h2 data-i18n='sec_doh'>Default resolver</h2>"
"    <div class='hint' data-i18n='doh_hint'></div>"
"    <div class='form-group'><label data-i18n='resolver_url'>Resolver address</label><input type='text' id='doh-url'></div>"
"    <button class='btn' onclick='saveDoh()' data-i18n='save_resolver_btn'>SAVE RESOLVER</button>"
"    <div id='doh-state' class='hint' style='margin-top:10px'></div>"
"    <div id='doh-suggest' class='hint'></div>"
""
"    <h2 data-i18n='sec_radio'>Radio</h2>"
"    <div id='radio-state' class='hint'></div>"
"    <div class='form-group'><label data-i18n='channel_width'>Channel width</label>"
"      <select id='bw-sel'><option value='40' data-i18n-opt='bw40'>40 MHz (HT40)</option><option value='20' data-i18n-opt='bw20'>20 MHz (HT20)</option></select></div>"
"    <button class='btn' onclick='saveRadio()' data-i18n='apply_btn'>APPLY</button>"
""
"    <h2 data-i18n='sec_perdev'>Per-device DNS</h2>"
"    <div class='hint' data-i18n='perdev_hint'></div>"
"    <div class='form-group'><label data-i18n='device_mac'>Device MAC</label><input type='text' id='dr-mac' placeholder='aa:bb:cc:dd:ee:ff'></div>"
"    <div class='form-group'><label data-i18n='protocol'>Protocol</label>"
"      <select id='dr-mode'><option value='doh' data-i18n-opt='doh_opt'>DoH (https:// URL)</option><option value='dot' data-i18n-opt='dot_opt'>DoT (IP, port 853)</option><option value='dns' data-i18n-opt='dns_opt'>Plain DNS (IP, port 53)</option></select></div>"
"    <div class='form-group'><label data-i18n='preset_label'>Preset</label><select id='dr-preset'></select></div>"
"    <div class='form-group'><label data-i18n='resolver_addr'>Resolver address</label><input type='text' id='dr-addr'></div>"
"    <div class='hint' data-i18n='preset_note'></div>"
"    <button class='btn' onclick='addDnsRule()' data-i18n='save_rule_btn'>SAVE RULE</button>"
"    <div style='margin-top:8px'><button class='btn small' onclick='runDnsTest()' data-i18n='test_btn'>TEST ALL RESOLVERS</button></div>"
"    <div id='dr-list' style='margin-top:12px'></div>"
"    <div id='dr-msg' class='hint' style='margin-top:10px'></div>"
""
"    <h2 data-i18n='sec_leases'>Static leases</h2>"
"    <div class='hint' data-i18n='leases_hint'></div>"
"    <div class='row form-group'><div><label data-i18n='mac_label'>MAC</label><input type='text' id='lease-mac' placeholder='aa:bb:cc:dd:ee:ff'></div><div><label data-i18n='ip_label'>IP</label><input type='text' id='lease-ip' placeholder='192.168.4.150'></div></div>"
"    <button class='btn' onclick='addLease()' data-i18n='add_lease_btn'>ADD LEASE</button>"
"    <div id='lease-list' style='margin-top:12px'></div>"
"    <div id='lease-msg' class='hint' style='margin-top:10px'></div>"
""
"    <h2 data-i18n='sec_fwd'>Port forwarding</h2>"
"    <div class='hint' data-i18n='fwd_hint'></div>"
"    <div id='pm-note' class='hint'></div>"
"    <div class='row form-group'><div><label data-i18n='proto_label'>Protocol</label><select id='pm-proto'><option value='tcp'>TCP</option><option value='udp'>UDP</option></select></div><div><label data-i18n='ext_port'>Ext port</label><input type='text' id='pm-mport' placeholder='8080'></div></div>"
"    <div class='row form-group'><div><label data-i18n='target_ip'>Target IP</label><input type='text' id='pm-daddr' placeholder='192.168.4.150'></div><div><label data-i18n='target_port'>Target port</label><input type='text' id='pm-dport' placeholder='80'></div></div>"
"    <button class='btn' onclick='addPortmap()' data-i18n='add_fwd_btn'>ADD FORWARD</button>"
"    <div id='pm-list' style='margin-top:12px'></div>"
"    <div id='pm-msg' class='hint' style='margin-top:10px'></div>"
""
"    <h2 data-i18n='sec_apctl'>AP controls</h2>"
"    <div class='form-group'><label data-i18n='hidden_label'>Hide SSID</label>"
"      <select id='ap-hidden'><option value='0'>OFF</option><option value='1'>ON</option></select>"
"      <div class='hint' style='margin:6px 0 0' data-i18n='hidden_hint'></div></div>"
"    <div class='row form-group'>"
"      <div><label data-i18n='maxconn_label'>Max clients</label><input type='text' id='ap-maxconn'></div>"
"      <div><label data-i18n='txpower_label'>TX power</label><input type='text' id='ap-txpower'></div>"
"    </div>"
"    <div class='hint' data-i18n='txpower_hint'></div>"
"    <div class='hint' data-i18n='restart_note'></div>"
"    <button class='btn' onclick='saveApCfg()' data-i18n='save_apctl_btn'>APPLY AP SETTINGS</button>"
""
"    <h2 data-i18n='sec_acl'>Client allow-list</h2>"
"    <div class='hint' data-i18n='acl_hint'></div>"
"    <div id='acl-state' class='hint'></div>"
"    <div class='row form-group'><div><label data-i18n='mac_label'>MAC</label><input type='text' id='acl-mac' placeholder='aa:bb:cc:dd:ee:ff'></div></div>"
"    <button class='btn small' onclick='aclAdd()' data-i18n='acl_add_btn'>ADD MAC</button>"
"    <div style='margin-top:8px'><button class='btn small' onclick='aclToggle()' id='acl-toggle-btn'>ENFORCE</button></div>"
"    <div id='acl-list' style='margin-top:12px'></div>"
"    <div id='acl-msg' class='hint' style='margin-top:10px'></div>"
""
"    <h2 data-i18n='sec_policy'>Device ownership</h2>"
"    <div class='form-group'><label><input type='checkbox' id='pol-claim' style='width:auto;margin-right:6px'><span data-i18n='guest_claim_label'></span></label>"
"      <div class='hint' style='margin:6px 0 0' data-i18n='guest_claim_hint'></div></div>"
"    <div class='form-group'><label><input type='checkbox' id='pol-clrvis' style='width:auto;margin-right:6px'><span data-i18n='clear_visit_label'></span></label>"
"      <div class='hint' style='margin:6px 0 0' data-i18n='clear_visit_hint'></div></div>"
"    <button class='btn' onclick='saveDevPolicy()' data-i18n='save_btn'>SAVE</button>"
""
"    <h2 data-i18n='sec_fw'>Firmware update</h2>"
"    <div class='hint' style='margin:0 0 10px'><span data-i18n='fw_current'></span>"
"      <b id='fw-version'>-</b> <span class='mono' id='fw-slot'></span></div>"
""
"    <div id='ota-devb' class='hint' style='display:none;margin:0 0 10px;color:#b45309' data-i18n='ota_devbuild'></div>"
""
"    <div>"
"      <div class='form-group'><label data-i18n='ota_freq'></label>"
"        <select id='ota-hours'>"
"          <option value='0' data-i18n='ota_freq_off'>Off</option>"
"          <option value='6' data-i18n='ota_freq_6h'>Every 6 hours</option>"
"          <option value='12' data-i18n='ota_freq_12h'>Every 12 hours</option>"
"          <option value='24' data-i18n='ota_freq_24h'>Daily</option>"
"          <option value='168' data-i18n='ota_freq_7d'>Weekly</option>"
"        </select></div>"
"      <div class='form-group'><label><input type='checkbox' id='ota-auto' style='width:auto;margin-right:6px'><span data-i18n='ota_auto'></span></label>"
"        <div class='hint' style='margin:6px 0 0' data-i18n='ota_auto_hint'></div></div>"
"      <div class='form-group'><label data-i18n='ota_buildrepo_label'></label><input type='text' id='ota-buildrepo' class='mono' readonly></div>"
"      <div class='form-group'><label data-i18n='ota_url_label'></label><input type='text' id='ota-url' placeholder='http://host/api/v1/repos/owner/repo/releases/latest'></div>"
"      <button class='btn' onclick='saveOtaCfg()' data-i18n='ota_save_btn'>SAVE SETTINGS</button>"
""
"      <div style='margin-top:14px;padding-top:12px;border-top:1px solid #e2e8f0'>"
"        <div id='ota-status' class='hint' style='margin:0 0 8px'></div>"
"        <progress id='ota-bar' max='100' value='0' style='display:none;width:100%;height:8px'></progress>"
"        <button class='btn' id='ota-check-btn' onclick='otaCheckNow()' data-i18n='ota_check_btn'>CHECK FOR UPDATES</button>"
"        <button class='btn danger' id='ota-install-btn' style='display:none' onclick='otaInstallNow()' data-i18n='ota_install_btn'>INSTALL</button>"
"        <div id='ota-msg' class='hint' style='margin:8px 0 0'></div>"
"      </div>"
"    </div>"
""
"    <h2 data-i18n='sec_upload'>Manual upload</h2>"
"    <div class='form-group'><label data-i18n='fw_file'></label><input type='file' id='fw-file' accept='.bin'></div>"
"    <progress id='fw-bar' max='100' value='0' style='display:none;width:100%;height:8px'></progress>"
"    <button class='btn danger' id='fw-btn' onclick='otaUpload()' data-i18n='fw_upload_btn'>UPLOAD AND RESTART</button>"
"    <div class='hint' style='margin:8px 0 0' data-i18n='fw_hint'></div>"
"    <div class='hint' style='margin:8px 0 0' data-i18n='fw_ap_note'></div>"
"    <div id='fw-msg' class='hint' style='margin-top:8px'></div>"
""
"    <h2 data-i18n='sec_dev'>Developer mode</h2>"
"    <div class='hint' style='margin:0 0 10px' data-i18n='dev_intro'></div>"
"    <div class='form-group'><label><input type='checkbox' id='dev-on' style='width:auto;margin-right:6px'><span data-i18n='dev_enable'></span></label>"
"      <div class='hint' style='margin:6px 0 0' data-i18n='dev_warn'></div></div>"
"    <div class='form-group'><label data-i18n='dev_token_label'></label>"
"      <input type='text' id='dev-token' class='mono' readonly placeholder='-'>"
"      <div class='hint' style='margin:6px 0 0' data-i18n='dev_token_hint'></div></div>"
"    <div class='row'>"
"      <div><button class='btn' onclick='saveDevMode()' data-i18n='save_btn'>SAVE</button></div>"
"      <div><button class='btn danger' id='dev-regen' onclick='regenDevToken()' data-i18n='dev_regen_btn'>NEW TOKEN</button></div>"
"    </div>"
"    <div class='form-group'><label data-i18n='dev_cmd_label'></label>"
"      <input type='text' id='dev-cmd' class='mono' readonly></div>"
"    <div id='dev-msg' class='hint' style='margin-top:8px'></div>"
""
"    <h2 data-i18n='sec_about'>About</h2>"
"    <div class='form-group'><label data-i18n='mdns_name'>mDNS name</label><input type='text' id='mdns-name'></div>"
"    <button class='btn' onclick='saveHostname()' data-i18n='save_mdns_btn'>SAVE NAME</button>"
"    <div id='settings-msg' class='hint' style='margin-top:10px'></div>"
"  </div>"
""
"  </div>"
"  <div class='footer'>"
"    <div data-i18n='footer_line'>EmbedWRT &middot; ESP32-S3 &middot; GPL v3</div>"
"    <div><a href='https://github.com/Svarkovsky/esp32-wifi-pocket' target='_blank'>based on esp32-wifi-pocket</a></div>"
"  </div>"
"</div>"
"<div id='modal' onclick='if(event.target===this)hideLogin()'>"
"  <div class='box'>"
"    <h3 data-i18n='login_title'>Administrator login</h3>"
"    <div class='form-group'><label data-i18n='login_user'>User</label><input type='text' id='lg-user'></div>"
"    <div class='form-group'><label data-i18n='login_pass'>Password</label><input type='password' id='lg-pass'></div>"
"    <div class='row'><div><button class='btn' onclick='doLogin()' data-i18n='login_submit'>LOG IN</button></div>"
"    <div><button class='btn' style='background:#e2e8f0;color:#475569' onclick='hideLogin()' data-i18n='login_cancel'>Cancel</button></div></div>"
"    <div class='err' id='lg-err'></div>"
"  </div>"
"</div>"
"<script>"
"var I18N={"
"en:{"
" title:'EmbedWRT',subtitle:'WiFi NAT router &middot; DoH / DoT',"
" tab_wifi:'WiFi',tab_clients:'Clients',tab_settings:'Settings',"
" wifi_setup:'Upstream WiFi',refresh:'Refresh',scanning_networks:'Scanning...',"
" ssid_label:'Network name',ssid_ph:'Network name',password_label:'Password',pass_ph:'Password',"
" connect_btn:'CONNECT',"
" checking:'Checking status...',connected_to:'Connected to:',not_connected:'Not connected',"
" clients_hint:'Signal is measured at this device, i.e. how well the client reaches the repeater. Per-client traffic volume is not tracked by the WiFi driver.',"
" sec_ap:'Access point',ap_name:'AP name (SSID)',ap_name_hint:'Changing this restarts WiFi: every client is dropped for a few seconds and the phone must rejoin. On iOS a new network name also means a new private MAC address, so MAC-based rules and leases must be re-added.',"
" save_name_btn:'SAVE NAME',cur_ap_pass:'Current password',new_ap_pass:'New password',new_pass_ph:'at least 8 characters',"
" change_pass_btn:'CHANGE PASSWORD',reset_btn:'RESET TO RANDOM',"
" sec_panel:'Web panel access',user_label:'User',panel_pass:'Panel password',panel_pass_ph:'empty = no password (open)',"
" save_auth_btn:'SAVE',auth_open:'No password set. This panel is reachable by anyone on the network.',auth_on:'Password is set.',"
" sec_doh:'Default resolver',doh_hint:'Used by devices with no per-device rule below.',"
" resolver_url:'Resolver address',save_resolver_btn:'SAVE RESOLVER',"
" sec_radio:'Radio',channel_width:'Channel width',bw40:'40 MHz (HT40)',bw20:'20 MHz (HT20, better at range)',apply_btn:'APPLY',"
" sec_perdev:'Per-device DNS',perdev_hint:'Leave empty to use the default resolver for every device.',"
" device_mac:'Device MAC',protocol:'Protocol',doh_opt:'DoH (https:// URL)',dot_opt:'DoT (IP, port 853)',dns_opt:'Plain DNS (IP, port 53)',"
" resolver_addr:'Resolver address',save_rule_btn:'SAVE RULE',test_btn:'TEST ALL RESOLVERS',preset_label:'Preset',preset_choose:'- pick a common resolver -',preset_cn:'Domestic (works here)',preset_foreign:'Foreign (blocked on this network)',preset_foreign_plain:'Foreign (reachable for plain DNS)',preset_note:'Foreign DoH and DoT are unreachable from this network: TCP 443 and 853 to them are filtered. Plain DNS to them does work. Pick a domestic one unless you know the path is open.',"
" sec_leases:'Static leases',leases_hint:'Pick an address outside the dynamic pool. iOS \"Private Wi-Fi Address\" rotates the MAC, which breaks MAC-based rules.',"
" mac_label:'MAC',ip_label:'IP',add_lease_btn:'ADD LEASE',"
" sec_fwd:'Port forwarding',fwd_hint:'Reachable from the upstream network only. The external address is what this device holds on the upstream side, and that address is itself behind the router NAT.',"
" proto_label:'Protocol',ext_port:'Ext port',target_ip:'Target IP',target_port:'Target port',add_fwd_btn:'ADD FORWARD',"
" sec_apctl:'AP controls',hidden_label:'Hide SSID',hidden_hint:'The network stops broadcasting its name. Clients must be told the name to join, and hidden networks are not actually more private - the name is still visible in the traffic.',"
" maxconn_label:'Max clients',txpower_label:'TX power (dBm)',txpower_hint:'Lowering this can reduce interference; range may suffer.',"
" save_apctl_btn:'APPLY AP SETTINGS',restart_note:'Changing hide-SSID or the client limit restarts the radio, so all clients drop for a few seconds.',"
" sec_acl:'Client allow-list',acl_hint:'NOT access control. ESP-IDF cannot refuse an association, so a disallowed client completes the handshake first and is then deauthenticated. It appears in the client list each time it retries. Treat this as a deterrent.',"
" acl_state_on:'Allow-list is ENFORCED.',acl_state_off:'Allow-list is off; every client may join.',"
" acl_add_btn:'ADD MAC',acl_enable_btn:'ENFORCE LIST',acl_disable_btn:'STOP ENFORCING',"
" acl_empty:'No MACs allowed yet.',acl_my_mac:'Your MAC',"
" sec_about:'About',mdns_name:'mDNS name',save_mdns_btn:'SAVE NAME',footer_line:'EmbedWRT &middot; ESP32-S3 &middot; GPL v3',"
" loading:'Loading...',no_clients:'No clients',cfg_btn:'Settings',iot_label:'IoT device',iot_hint:'An IoT device can be managed by its owner without logging in.',owner_label:'Owner',owner_none:'(unowned)',save_dev_btn:'SAVE',claim_btn:'Claim',release_btn:'Release',sec_policy:'Device ownership',guest_claim_label:'Allow visitors to claim unowned IoT devices',guest_claim_hint:'A visitor can take an unowned IoT device without logging in, and release it again. Only unowned ones, so one visitor cannot take a device another already manages.',clear_visit_label:'Drop the IoT flag when that device opens the panel',clear_visit_hint:'Anything able to open a web UI is not a dumb IoT device. Only affects the device that visits.',claimable_hint:'Unowned - a visitor may claim this.',your_device:'Your device',guest_devices:'Devices you can manage',device_offline:'offline',"
" sec_fw:'Firmware update',fw_current:'Installed version',fw_slot:'slot',fw_file:'Firmware file (.bin)',"
" fw_hint:'Upload build/embedwrt.bin - the application image. The merged full-flash image will not work here.',"
" fw_upload_btn:'UPLOAD AND RESTART',"
" fw_confirm:'Write this firmware to the device? It will restart and every client will drop.',"
" fw_uploading:'Uploading',fw_ok:'Firmware written. The device is restarting.',"
" fw_wait:'Waiting for the device to come back',fw_relogin:'The device restarted. Log in again to check the new version.',"
" fw_failed:'Update failed',fw_nofile:'Choose a firmware file first',"
" fw_noback:'The device did not come back. Reload this page to check.',"
" fw_ap_note:'The upload takes a minute over WiFi, and DNS and forwarding will stutter while it writes. The access point stays up until the restart.',"
" sec_upload:'Manual upload',"
" ota_freq:'Check for updates',ota_freq_off:'Off',ota_freq_6h:'Every 6 hours',ota_freq_12h:'Every 12 hours',ota_freq_24h:'Daily',ota_freq_7d:'Weekly',"
" ota_auto:'Install new versions without asking',"
" ota_auto_hint:'Off by default: a restart drops every client, so the device waits for you. With this on it installs as soon as it finds a newer release.',"
" ota_url_label:'Release feed URL',ota_save_btn:'SAVE SETTINGS',"
" ota_devbuild:'This is a development build, so it never checks or installs on its own. Checking and installing by hand still work, which is what you want while working on the update path. Automatic updating is compiled in only for release builds - what CI produces on a tag.',"
" ota_buildrepo_label:'Built from',ota_repo_unknown:'(unknown source)',"
" ota_check_btn:'CHECK FOR UPDATES',ota_checking:'Checking',ota_uptodate:'Up to date',"
" ota_available:'Version {v} is available.',ota_install_btn:'INSTALL AND RESTART',"
" ota_downloading:'Downloading',ota_installing:'Written and verified; restarting',"
" ota_lastcheck:'Last checked',ota_never:'never',ota_failed:'Update check failed',"
" ota_ago_min:'{n} min ago',ota_ago_hour:'{n} h ago',ota_ago_day:'{n} d ago',"
" ota_install_confirm:'Install the new firmware and restart? Every client will drop.',"
" sec_dev:'Developer mode',"
" dev_intro:'Lets a script flash firmware without logging in, by presenting a token in a request header.',"
" dev_enable:'Allow firmware updates with a token instead of a login',"
" dev_warn:'The token can replace the firmware, which is the most powerful thing this device does. It is sent in the clear, like the panel password, so anyone who can watch the network can read it. Leave this off unless you are automating updates.',"
" dev_token_label:'Token',dev_token_hint:'Stored on the device. Generate a new one if it leaks.',"
" dev_regen_btn:'NEW TOKEN',"
" dev_cmd_label:'Example',"
" dev_off:'Developer mode is off. Enable it to get a token.',"
" dev_on:'Developer mode is on. Anyone with the token can flash this device.',"
" dev_token_changed:'New token generated. Update anything using the old one.',"
" dev_need_on:'Enable developer mode first.',"
" login_btn:'Log in',logout_btn:'Log out',login_title:'Administrator login',"
" login_user:'User',login_pass:'Password',login_submit:'LOG IN',login_cancel:'Cancel',"
" login_failed:'Wrong user or password',login_ok:'Signed in',"
" guest_body:'Signed out. You can manage this device below, or log in as administrator.',"
" guest_you:'Your address',"
" guest_noident:'This address does not belong to a device on this network, so there is nothing to show. Log in as administrator for full access.',"
" session_open:'No admin password is set, so the panel is open to anyone who can reach it.',lease_for:'Static lease for this device',dns_for:'DNS for this device',save_btn:'SAVE',remove_btn:'REMOVE',set_mark:'set',not_set:'not set',use_default_dns:'(none - uses the default resolver)',no_rules:'No rules',no_leases:'No static leases',no_forwards:'No rules',no_networks:'No networks',scan_failed:'Scan failed',failed_load:'Failed to load',"
" active:'(active)',delete:'delete',uptime:'up',unknown:'unknown',"
" confirm_lease:'Remove the lease for',confirm_rule:'Remove the DNS rule for',confirm_fwd:'Remove',"
" enter_both:'Fill in all fields',rejected:'Rejected',saved:'Saved.',applied:'Applied.',failed:'Failed',"
" already_connected:'Already connected to',enter_ssid:'Enter a network name',"
" pass_short:'Password must be at least 8 characters',pass_changed:'Password changed. You may need to reconnect.',pass_failed:'Failed to change password.',"
" reset_confirm:'Reset the AP password to a new random value? You will need to reconnect.',reset_done:'AP password reset. The page will reload.',reset_failed:'Failed to reset password.',"
" testing:'Testing each resolver with a real query; this takes a few seconds per entry...',test_failed:'Test request failed',"
" doh_mode_doh:'DoH',doh_mode_plain:'plaintext fallback',doh_mode_none:'off',doh_mode_idle:'idle (no lookup yet)',doh_mode_clock:'waiting for the clock',"
" pool_free:'Addresses outside',pool_in_use:'are handed out dynamically.',"
" lease_note:'The client picks it up on its next request.',"
" fwd_external:'Reachable from the upstream network at',"
" fwd_no_ext:'No upstream address yet.',"
" no_pass_set:'No password set',"
" enable_btn:'ENABLE',disable_btn:'DISABLE'"
"},"
"zh:{"
" title:'EmbedWRT',subtitle:'WiFi 中继路由器 &middot; DoH / DoT',"
" tab_wifi:'WiFi',tab_clients:'客户端',tab_settings:'设置',"
" wifi_setup:'上级 WiFi',refresh:'刷新',scanning_networks:'正在扫描...',"
" ssid_label:'网络名称',ssid_ph:'网络名称',password_label:'密码',pass_ph:'密码',"
" connect_btn:'连 接',"
" checking:'正在检查状态...',connected_to:'已连接到：',not_connected:'未连接',"
" clients_hint:'这里显示的是本机测到的信号，即客户端到中继的连接质量。WiFi 驱动不统计每个客户端的流量。',"
" sec_ap:'热点',ap_name:'热点名称（SSID）',ap_name_hint:'修改会重启 WiFi：所有客户端会断开几秒，手机需要重新加入。iOS 上换网络名还会换一个新的随机 MAC，所以按 MAC 的规则和租约都需要重新添加。',"
" save_name_btn:'保存名称',cur_ap_pass:'当前密码',new_ap_pass:'新密码',new_pass_ph:'至少 8 个字符',"
" change_pass_btn:'修改密码',reset_btn:'重置为随机密码',"
" sec_panel:'管理面板访问',user_label:'用户名',panel_pass:'面板密码',panel_pass_ph:'留空 = 不设密码（开放）',"
" save_auth_btn:'保存',auth_open:'未设置密码。局域网内任何人都能打开并修改本面板。',auth_on:'已设置密码。',"
" sec_doh:'默认解析器',doh_hint:'未单独指定规则的设备使用这一项。',"
" resolver_url:'解析器地址',save_resolver_btn:'保存解析器',"
" sec_radio:'射频',channel_width:'信道宽度',bw40:'40 MHz (HT40)',bw20:'20 MHz (HT20，远距离更好)',apply_btn:'应用',"
" sec_perdev:'按设备指定 DNS',perdev_hint:'留空表示所有设备都用上面的默认解析器。',"
" device_mac:'设备 MAC',protocol:'协议',doh_opt:'DoH（https:// 地址）',dot_opt:'DoT（IP，端口 853）',dns_opt:'明文 DNS（IP，端口 53）',"
" resolver_addr:'解析器地址',save_rule_btn:'保存规则',test_btn:'测试所有解析器',preset_label:'预设',preset_choose:'- 选择常用解析器 -',preset_cn:'国内（本网络可用）',preset_foreign:'国外（本网络不可达）',preset_foreign_plain:'国外（明文 DNS 可达）',preset_note:'国外的 DoH 和 DoT 在本网络不可达：到它们的 TCP 443 和 853 被拦截。国外明文 DNS 是通的。除非确认链路已开放，否则建议用国内。',"
" sec_leases:'静态租约',leases_hint:'请选一个动态地址池之外的地址。iOS 的「私有 Wi-Fi 地址」会轮换 MAC，会让按 MAC 的规则失效。',"
" mac_label:'MAC',ip_label:'IP',add_lease_btn:'添加租约',"
" sec_fwd:'端口转发',fwd_hint:'只能从上级网络访问：外部地址是本机在上级网络的地址，而它本身还在路由器的 NAT 后面。',"
" proto_label:'协议',ext_port:'外部端口',target_ip:'目标 IP',target_port:'目标端口',add_fwd_btn:'添加转发',"
" sec_apctl:'热点控制',hidden_label:'隐藏 SSID',hidden_hint:'不再广播网络名。客户端必须知道名字才能加入；而且隐藏网络并不真的更私密——名字仍会出现在无线流量里。',"
" maxconn_label:'最大客户端数',txpower_label:'发射功率（dBm）',txpower_hint:'降低可减少干扰，但覆盖距离可能变差。',"
" save_apctl_btn:'应用热点设置',restart_note:'修改隐藏 SSID 或客户端上限会重启射频，所有客户端会断开几秒。',"
" sec_acl:'客户端白名单',acl_hint:'这不是真正的接入控制。ESP-IDF 无法在关联时拒绝，所以不在名单上的客户端会先完成握手，然后被踢下线。它每次重试都会出现在客户端列表里。只能当作威慢手段。',"
" acl_state_on:'白名单已生效。',acl_state_off:'白名单已关闭，任何客户端都能加入。',"
" acl_add_btn:'添加 MAC',acl_enable_btn:'启用名单',acl_disable_btn:'停止过滤',"
" acl_empty:'尚未添加任何 MAC。',acl_my_mac:'本机 MAC',"
" sec_about:'关于',mdns_name:'mDNS 名称',save_mdns_btn:'保存名称',footer_line:'EmbedWRT &middot; ESP32-S3 &middot; GPL v3',"
" loading:'加载中...',no_clients:'暂无客户端',cfg_btn:'设置',iot_label:'物联网设备',iot_hint:'标记为物联网设备后，其主人无需登录即可管理它。',owner_label:'主人',owner_none:'（未指派）',save_dev_btn:'保存',claim_btn:'认领',release_btn:'放弃',sec_policy:'设备归属',guest_claim_label:'允许访客认领无主的物联网设备',guest_claim_hint:'访客无需登录即可认领无主的物联网设备，也可以放弃。只限无主的，所以不会抢走别人已在管理的设备。',clear_visit_label:'该设备打开面板时自动取消其物联网标记',clear_visit_hint:'能自己打开网页的就不算哑设备。只影响访问面板的那台设备本身。',claimable_hint:'无主 - 访客可以认领。',your_device:'你的设备',guest_devices:'你可以管理的设备',device_offline:'离线',"
" sec_fw:'固件更新',fw_current:'当前固件：',fw_slot:'槽位',fw_file:'固件文件（.bin）',"
" fw_hint:'请上传 build/embedwrt.bin，即应用程序镜像。合并后的整片烧录镜像不能用于此处。',"
" fw_upload_btn:'上传并重启',"
" fw_confirm:'确定把该固件写入设备？设备会重启，所有客户端都会断开。',"
" fw_uploading:'上传中',fw_ok:'固件已写入，设备正在重启。',"
" fw_wait:'等待设备重新上线',fw_relogin:'设备已重启。请重新登录以确认新版本。',"
" fw_failed:'更新失败',fw_nofile:'请先选择固件文件',"
" fw_noback:'设备没有回应。请刷新本页查看。',"
" fw_ap_note:'通过 WiFi 上传约需一分钟，写入期间 DNS 和转发会短暂卡顿。热点会保持到重启那一刻。',"
" sec_upload:'手动上传',"
" ota_freq:'检查更新频率',ota_freq_off:'关闭',ota_freq_6h:'每 6 小时',ota_freq_12h:'每 12 小时',ota_freq_24h:'每天',ota_freq_7d:'每周',"
" ota_auto:'发现新版本直接安装，不询问',"
" ota_auto_hint:'默认关闭：重启会踢掉所有客户端，所以由你决定时机。开启后会一发现新版本就自动安装。',"
" ota_url_label:'发布源地址',ota_save_btn:'保存设置',"
" ota_devbuild:'这是开发构建，不会自行检查或安装更新。手动检查和手动安装仍然可用 —— 开发更新功能时正是需要这个。自动更新只编译进正式发布版本，也就是 CI 在打 tag 时产出的那一版。',"
" ota_buildrepo_label:'构建来源',ota_repo_unknown:'（来源未知）',"
" ota_check_btn:'检查更新',ota_checking:'检查中',ota_uptodate:'已是最新',"
" ota_available:'发现新版本 {v}。',ota_install_btn:'安装并重启',"
" ota_downloading:'下载中',ota_installing:'已写入并校验通过，正在重启',"
" ota_lastcheck:'上次检查',ota_never:'从未',ota_failed:'检查更新失败',"
" ota_ago_min:'{n} 分钟前',ota_ago_hour:'{n} 小时前',ota_ago_day:'{n} 天前',"
" ota_install_confirm:'确定安装新固件并重启？所有客户端都会断开。',"
" sec_dev:'开发者模式',"
" dev_intro:'允许脚本在请求头里附带令牌，无需登录即可刷写固件。',"
" dev_enable:'允许用令牌（而非登录）更新固件',"
" dev_warn:'令牌可以直接替换固件，这是本设备权限最高的操作。它和面板密码一样是明文传输的，能监听网络的人就能读到。除非你要做自动化更新，否则保持关闭。',"
" dev_token_label:'令牌',dev_token_hint:'保存在设备上。若泄漏请生成新的。',"
" dev_regen_btn:'生成新令牌',"
" dev_cmd_label:'示例',"
" dev_off:'开发者模式已关闭。启用后会生成令牌。',"
" dev_on:'开发者模式已开启。持有令牌的人都能刷写本设备。',"
" dev_token_changed:'已生成新令牌。请更新所有使用旧令牌的地方。',"
" dev_need_on:'请先启用开发者模式。',"
" login_btn:'登录',logout_btn:'退出登录',login_title:'管理员登录',"
" login_user:'用户名',login_pass:'密码',login_submit:'登 录',login_cancel:'取消',"
" login_failed:'用户名或密码错误',login_ok:'已登录',"
" guest_body:'未登录。可在下方管理本机设备，或以管理员身份登录。',"
" guest_you:'你的地址',"
" guest_noident:'这个地址不属于本网络上的设备，因此没有可显示的内容。以管理员身份登录可获得完整权限。',"
" session_open:'未设置管理员密码，能访问到本面板的人都可以操作。',lease_for:'该设备的静态租约',dns_for:'该设备的 DNS',save_btn:'保存',remove_btn:'移除',set_mark:'已设置',not_set:'未设置',use_default_dns:'（未设置 - 使用默认解析器）',no_rules:'暂无规则',no_leases:'暂无静态租约',no_forwards:'暂无规则',no_networks:'未发现网络',scan_failed:'扫描失败',failed_load:'加载失败',"
" active:'（当前）',delete:'删除',uptime:'在线',unknown:'未知',"
" confirm_lease:'确定删除该设备的静态租约：',confirm_rule:'确定删除该设备的 DNS 规则：',confirm_fwd:'确定删除',"
" enter_both:'请填写完整',rejected:'被拒绝',saved:'已保存。',applied:'已应用。',failed:'失败',"
" already_connected:'已经连接到',enter_ssid:'请输入网络名称',"
" pass_short:'密码至少需要 8 个字符',pass_changed:'密码已修改，可能需要重新连接。',pass_failed:'修改密码失败。',"
" reset_confirm:'确定把热点密码重置为新的随机值？之后需要重新连接。',reset_done:'热点密码已重置，页面将重新加载。',reset_failed:'重置密码失败。',"
" testing:'正在用真实查询逐个测试解析器，每项可能需要几秒...',test_failed:'测试请求失败',"
" doh_mode_doh:'DoH 加密',doh_mode_plain:'降级为明文',doh_mode_none:'未启用',doh_mode_idle:'空闲（尚无查询）',doh_mode_clock:'等待对时',"
" pool_free:'动态地址池之外的',pool_in_use:'会被动态分配。',"
" lease_note:'客户端下次请求时生效。',"
" fwd_external:'可从上级网络访问：',"
" fwd_no_ext:'还没有上级地址。',"
" no_pass_set:'未设置密码',"
" enable_btn:'启用',disable_btn:'停用'"
"}"
"};"
"var LANG='en';"
"try{var sv=localStorage.getItem('embedwrt_lang');if(sv){LANG=sv}else if((navigator.language||'').toLowerCase().indexOf('zh')===0){LANG='zh'}}catch(e){}"
"function t(k){var d=I18N[LANG]||I18N.en;var v=d[k];if(v===undefined){v=I18N.en[k]}return (v===undefined)?k:v}"
"function toggleLang(){LANG=(LANG==='zh')?'en':'zh';try{localStorage.setItem('embedwrt_lang',LANG)}catch(e){}applyLang()}"
"function applyLang(){"
"  document.documentElement.lang=(LANG==='zh')?'zh-CN':'en';"
"  var els=document.querySelectorAll('[data-i18n]');"
"  for(var i=0;i<els.length;i++){els[i].innerHTML=t(els[i].getAttribute('data-i18n'))}"
"  var ph=document.querySelectorAll('[data-i18n-ph]');"
"  for(var j=0;j<ph.length;j++){ph[j].placeholder=t(ph[j].getAttribute('data-i18n-ph'))}"
"  var op=document.querySelectorAll('[data-i18n-opt]');"
"  for(var k=0;k<op.length;k++){op[k].textContent=t(op[k].getAttribute('data-i18n-opt'))}"
"  document.getElementById('lang-btn').textContent=(LANG==='zh')?'EN':'中文';"
"  var ab=document.getElementById('auth-btn');"
"  if(ab && SESSION.auth_enabled){ ab.textContent=(SESSION.role==='admin')?t('logout_btn'):t('login_btn') }"
"  refreshActiveTab();"
"}"
"var DOH_STATE={doh:'doh_mode_doh',plain:'doh_mode_plain',off:'doh_mode_none',idle:'doh_mode_idle',clock:'doh_mode_clock'};"
"function dohText(m){return t(DOH_STATE[m]||'doh_mode_plain')}"
"function refreshActiveTab(){"
"  /* Role-aware: a guest must not issue admin requests at all. Without this"
"     guard applyLang() -> refreshActiveTab() -> init() fired /status and /scan"
"     for visitors, which came back 401 and filled the console with errors. */"
"  if(SESSION.role!=='admin'){return}"
"  if(document.getElementById('tab-wifi').classList.contains('active')){init()}"
"  else if(document.getElementById('tab-clients').classList.contains('active')){loadClients()}"
"  else{loadSettings(loadGen)}"
"}"
"function switchTab(tab,ev){"
"  var tabs=document.querySelectorAll('.tab'),cs=document.querySelectorAll('.tab-content');"
"  for(var i=0;i<tabs.length;i++){tabs[i].classList.remove('active')}"
"  for(var j=0;j<cs.length;j++){cs[j].classList.remove('active')}"
"  if(ev&&ev.target){ev.target.classList.add('active')}"
"  document.getElementById('tab-'+tab).classList.add('active');"
"  refreshActiveTab();"
"}"
"function initPresets(){"
"  wirePresets(document.getElementById('dr-mode'),"
"              document.getElementById('dr-preset'),"
"              document.getElementById('dr-addr'));"
"}"
"/* Sequential on purpose. Firing every section's request at once exceeds the"
"   httpd socket limit (max_open_sockets defaults to 7), and the panels for"
"   whatever loses the race render empty. Chaining keeps the socket count at one"
"   no matter how many sections are added later, and these requests are tiny on a"
"   LAN, so the limit should never be reached at all. */"
"/* Fetch several endpoints one at a time and collect the results in order."
"   Serialised for the same reason loadSettings is: the httpd socket limit is 7"
"   and a page that opens several panels at once would otherwise reset some. */"
"function fetchSeq(urls){"
"  var out=[], p=Promise.resolve();"
"  urls.forEach(function(u,i){"
"    p=p.then(function(){"
"      return fetch(u).then(function(r){ return r.ok?r.json():null })"
"                    .then(function(d){ out[i]=d });"
"    });"
"  });"
"  return p.then(function(){ return out });"
"}"
"function runSequential(fns,gen){"
"  var p=Promise.resolve();"
"  fns.forEach(function(f){"
"    p=p.then(function(){"
"      if(gen!==undefined && gen!==loadGen){return}   /* superseded: stop */"
"      return f();"
"    });"
"  });"
"  return p;"
"}"
"function loadSettings(gen){"
"  return runSequential([loadSsid,loadAuth,loadDoh,loadRadio,loadApCfg,loadAcl,loadDevPolicy,"
"                        loadLeases,loadDnsRules,loadPortmaps,loadHostname,loadFwInfo,"
"                        loadDevMode],gen);"
"}"
"function init(){"
"  fetch('/status').then(function(r){return r.json()}).then(function(d){"
"    var msg=document.getElementById('status-msg');"
"    if(d.status==='connected'){"
"      msg.innerHTML=t('connected_to')+' <b>'+d.ssid+'</b>';"
"      msg.style.color='#15803d';msg.style.background='#f0fdf4';"
"    }else{"
"      msg.innerHTML=t('not_connected');"
"      msg.style.color='#b91c1c';msg.style.background='#fef2f2';"
"    }"
"    var dm=document.getElementById('dns-msg');"
"    var mode=d.doh||'';"
"    dm.innerHTML='DNS: '+dohText(mode)+(mode==='doh'?' ✓':'');"
"    scan();"
"  }).catch(function(){});"
"}"
"var lockSvg='<svg class=\"icon secure\" viewBox=\"0 0 24 24\"><path d=\"M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z\"/></svg>';"
"var wifiSvg='<svg class=\"icon\" viewBox=\"0 0 24 24\"><path d=\"M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z\"/></svg>';"
"var curSsid='';"
"function scan(){"
"  var lst=document.getElementById('list');lst.innerHTML='<div class=\"loading\">'+t('scanning_networks')+'</div>';"
"  fetch('/scan').then(function(r){return r.json()}).then(function(data){"
"    lst.innerHTML='';"
"    if(!data.length){lst.innerHTML='<div class=\"loading\">'+t('no_networks')+'</div>';return}"
"    data.forEach(function(net){"
"      var div=document.createElement('div');div.className='network-item';"
"      if(net.ssid===curSsid){div.style.background='#f0fdf4';div.style.borderLeft='3px solid #22c55e'}"
"      div.onclick=function(){document.getElementById('ssid').value=net.ssid};"
"      div.innerHTML=\"<div class='net-info'>\"+net.ssid+(net.ssid===curSsid?' <b>'+t('active')+'</b>':'')+\"</div><div class='net-icons'>\"+(net.sec?lockSvg:'')+wifiSvg+\"</div>\";"
"      lst.appendChild(div);"
"    });"
"  }).catch(function(){lst.innerHTML='<div class=\"loading\">'+t('scan_failed')+'</div>'});"
"}"
"function connect(){"
"  var s=document.getElementById('ssid').value,p=document.getElementById('pwd').value;"
"  if(!s){alert(t('enter_ssid'));return}"
"  if(s===curSsid){alert(t('already_connected')+' '+s);return}"
"  var btn=event.target;btn.innerText='...';btn.style.background='#94a3b8';"
"  fetch('/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(s)+'&pass='+encodeURIComponent(p)})"
"  .then(function(){alert(t('saved')+' ')})"
"  .finally(function(){btn.innerText=t('connect_btn');btn.style.background='#3b82f6';setTimeout(init,3000)});"
"}"
"var CD_MODEKEY={doh:'doh_opt',dot:'dot_opt',dns:'dns_opt'};"
"function loadClients(){"
"  var box=document.getElementById('client-list');"
"  fetch('/api/clients').then(function(r){return r.json()}).then(function(d){"
"    if(!d.length){box.innerHTML='<div class=\"loading\">'+t('no_clients')+'</div>';return}"
"    var h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.forEach(function(c){"
"      var r=c.rssi,col=(r>-60)?'#15803d':((r>-70)?'#b45309':'#b91c1c');"
"      var id=c.mac.replace(/:/g,'');"
"      /* The row is not clickable and the card is its SIBLING, not its child."
"         Nested inside a clickable row, a click on a card button bubbled up to"
"         the row's handler, which toggled the card shut and cleared the"
"         reopen state before the save had even returned - so the card collapsed"
"         on every save and the result message went with it. */"
"      h+=\"<div style='border-bottom:1px solid #e2e8f0'>\""
"        +\"<div class='network-item' style='cursor:default;border-bottom:none'>\""
"        +\"<div style='flex:1;min-width:0'>\""
"        +\"<div style='display:flex;justify-content:space-between;align-items:center;gap:8px'>\""
"        +\"<span class='mono' style='font-size:12px;overflow:hidden;text-overflow:ellipsis'>\"+c.mac+\"</span>\""
"        +\"<span style='color:\"+col+\";font-weight:700;font-size:13px;white-space:nowrap'>\"+r+\" dBm</span></div>\""
"        +\"<div style='font-size:12px;color:#475569;margin-top:4px;overflow:hidden;text-overflow:ellipsis'>\"+c.ip"
"        +(c.host?(\" &middot; \"+c.host):\"\")+\" &middot; \"+t('uptime')+\" \"+Math.floor(c.uptime/60)+\"m</div>\""
"        +\"</div>\""
"        +\"<button class='refresh-btn' style='flex:0 0 auto;margin-left:10px' onclick='toggleClient(\\\"\"+id+\"\\\")'>&#9881; \"+t('cfg_btn')+\"</button>\""
"        +\"</div>\""
"        +\"<div id='cd-\"+id+\"' data-mac='\"+c.mac+\"' data-ip='\"+c.ip+\"' style='display:none'></div>\""
"        +\"</div>\";"
"    });"
"    box.innerHTML=h+'</div>';"
"    /* Re-open and reload whichever card was expanded before, so a save does not"
"       silently collapse it and hide the result message. A block comment, not a"
"       line comment: the C literal is built line by line with the newlines"
"       removed, so a // comment would swallow the rest of the whole script. */"
"    if(openClientId){"
"      var el=document.getElementById('cd-'+openClientId);"
"      if(el){ el.style.display='block'; loadClientDetail(el,openClientId,keepMsg); }"
"      else { openClientId=null; }"
"    }"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"var openClientId=null;"
"var keepMsg=null;"
"function toggleClient(id){"
"  var el=document.getElementById('cd-'+id);"
"  if(!el){return}"
"  if(el.style.display==='block'){openClientId=null;keepMsg=null;el.style.display='none';return}"
"  openClientId=id;keepMsg=null;"
"  el.style.display='block';"
"  loadClientDetail(el,id);"
"}"
"/* The lease + DNS half of a device card. Shared by the admin Clients tab and the"
"   guest view, so both edit a device the same way. */"
"function deviceEditHtml(id,mac,lease,rule,L,curIp){"
"  var suggest=curIp||'';"
"  if(lease){suggest=lease.ip}"
"  else if(L&&L.pool_known){"
"    var q=L.pool_last.split('.');"
"    suggest=q[0]+'.'+q[1]+'.'+q[2]+'.'+(parseInt(q[3],10)+1);"
"  }"
"  var h=\"\";"
"  h+=\"<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>\";"
"  h+=\"<label>\"+t('lease_for')+\" <span style='color:\"+(lease?'#15803d':'#94a3b8')+\"'>(\""
"    +(lease?t('set_mark'):t('not_set'))+\")</span></label>\";"
"  h+=\"<div class='row'><div><input type='text' id='cd-ip-\"+id+\"' value='\"+suggest+\"'></div>\""
"    +\"<div style='flex:0 0 auto'><button class='refresh-btn' onclick='cdSaveLease(\\\"\"+mac+\"\\\",\\\"\"+id+\"\\\")'>\"+t('save_btn')+\"</button></div>\""
"    +(lease?\"<div style='flex:0 0 auto'><button class='refresh-btn' onclick='cdDelLease(\\\"\"+mac+\"\\\",\\\"\"+id+\"\\\")'>\"+t('remove_btn')+\"</button></div>\":\"\")"
"    +\"</div>\";"
"  if(L&&L.pool_known){"
"    h+=\"<div class='hint' style='margin:6px 0 0'>\"+t('pool_free')+\" \"+L.pool_first+\"-\"+L.pool_last+\" \"+t('pool_in_use')+\"</div>\";"
"  }"
"  h+=\"</div>\";"
"  h+=\"<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>\";"
"  h+=\"<label>\"+t('dns_for')+\" <span style='color:\"+(rule?'#15803d':'#94a3b8')+\"'>(\""
"    +(rule?t('set_mark'):t('use_default_dns'))+\")</span></label>\";"
"  h+=\"<div class='row'><div><select id='cd-mode-\"+id+\"'>\";"
"  ['doh','dot','dns'].forEach(function(m){"
"    h+=\"<option value='\"+m+\"'\"+(rule&&rule.mode===m?' selected':'')+\">\"+t(CD_MODEKEY[m])+\"</option>\";"
"  });"
"  h+=\"</select></div></div>\";"
"  h+=\"<div class='form-group' style='margin-top:8px'><label>\"+t('preset_label')+\"</label>\""
"    +\"<select id='cd-preset-\"+id+\"'></select></div>\";"
"  h+=\"<div class='row form-group'><div><input type='text' id='cd-addr-\"+id+\"' value='\""
"    +(rule?rule.addr:'')+\"' placeholder='223.5.5.5'></div></div>\";"
"  h+=\"<div class='row'><div><button class='refresh-btn' style='width:100%' onclick='cdSaveRule(\\\"\"+mac+\"\\\",\\\"\"+id+\"\\\")'>\"+t('save_btn')+\"</button></div>\""
"    +(rule?\"<div><button class='refresh-btn' style='width:100%' onclick='cdDelRule(\\\"\"+mac+\"\\\",\\\"\"+id+\"\\\")'>\"+t('remove_btn')+\"</button></div>\":\"\")"
"    +\"</div>\";"
"  h+=\"<div class='hint' style='margin:8px 0 0' id='cd-msg-\"+id+\"'></div>\";"
"  h+=\"</div>\";"
"  return h;"
"}"
"/* The admin-only half: IoT flag and owner. */"
"function deviceAttrHtml(id,mac,rec,clients){"
"  var h=\"<div style='padding:12px 14px;background:#f8fafc;border-top:1px solid #e2e8f0'>\";"
"  h+=\"<label><input type='checkbox' id='cd-iot-\"+id+\"' style='width:auto;margin-right:6px'\""
"    +((rec&&rec.iot)?' checked':'')+\">\"+t('iot_label')+\"</label>\";"
"  h+=\"<div class='hint' style='margin:6px 0 0'>\"+t('iot_hint')+\"</div>\";"
"  h+=\"<div class='form-group' style='margin:10px 0 0'><label>\"+t('owner_label')+\"</label><select id='cd-owner-\"+id+\"'>\";"
"  h+=\"<option value=''>\"+t('owner_none')+\"</option>\";"
"  (clients||[]).forEach(function(c){"
"    if(c.mac===mac){return}"
"    h+=\"<option value='\"+c.mac+\"'\"+(rec&&rec.owner===c.mac?' selected':'')+\">\""
"      +c.mac+(c.host?(' ('+c.host+')'):'')+\"</option>\";"
"  });"
"  h+=\"</select></div>\";"
"  h+=\"<button class='refresh-btn' style='width:100%' onclick='cdSaveDevice(\\\"\"+mac+\"\\\",\\\"\"+id+\"\\\")'>\"+t('save_dev_btn')+\"</button>\";"
"  h+=\"</div>\";"
"  return h;"
"}"
"function loadClientDetail(el,id,msg)  {"
"  el.innerHTML='<div class=\"loading\">'+t('loading')+'</div>';"
"  var mac=el.getAttribute('data-mac'),curIp=el.getAttribute('data-ip');"
"  fetchSeq(['/api/leases','/api/dnsrules','/api/devices','/api/clients']).then(function(res){"
"    var L=res[0]||{},R=res[1]||{},D=res[2]||{},C=res[3]||[];"
"    var lease=null;(L.leases||[]).forEach(function(x){if(x.mac===mac){lease=x}});"
"    var rule=null;(R.rules||[]).forEach(function(x){if(x.mac===mac){rule=x}});"
"    var rec=null;(D.devices||[]).forEach(function(x){if(x.mac===mac){rec=x}});"
"    el.innerHTML=deviceEditHtml(id,mac,lease,rule,L,curIp)+deviceAttrHtml(id,mac,rec,C);"
"    wirePresets(document.getElementById('cd-mode-'+id),"
"                document.getElementById('cd-preset-'+id),"
"                document.getElementById('cd-addr-'+id));"
"    if(msg){cdMsg(id,msg.ok,msg.txt)}"
"  }).catch(function(){el.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"function cdSaveDevice(mac,id){"
"  var rec=null,cb=document.getElementById('cd-iot-'+id);"
"  var iot=(cb&&cb.checked)?'1':'0';"
"  var owner=(document.getElementById('cd-owner-'+id)||{}).value||'';"
"  var m=document.getElementById('cd-msg-'+id);"
"  fetch('/device/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'mac='+encodeURIComponent(mac)+'&iot='+iot+'&owner='+encodeURIComponent(owner)})"
"  .then(function(r){return r.text().then(function(x){"
"    if(m){m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>')"
"                         :('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>')}"
"  })});"
"}"
"/* The guest's devices: its own entry, the IoT devices it owns, and - when"
"   claiming is enabled - unowned IoT devices it could take. Driven by /api/devices"
"   (which knows the claim flags and includes offline devices) unioned with"
"   /api/clients (which has the live hostname and address). */"
"function loadGuestView(msg){"
"  var box=document.getElementById('guest-devices');"
"  box.innerHTML='<div class=\"loading\">'+t('loading')+'</div>';"
"  fetchSeq(['/api/devices','/api/clients','/api/leases','/api/dnsrules']).then(function(res){"
"    var D=res[0]||{},C=res[1]||[],L=res[2]||{},R=res[3]||{};"
"    var me=D.me||'';"
"    var rec={};(D.devices||[]).forEach(function(d){rec[d.mac]=d});"
"    var live={};C.forEach(function(c){live[c.mac]=c});"
"    var seen={},order=[];"
"    function add(m){if(m&&!seen[m]){seen[m]=1;order.push(m)}}"
"    /* This device first: it is the one the visitor came to configure. */"
"    add(me);"
"    (D.devices||[]).forEach(function(d){add(d.mac)});"
"    C.forEach(function(c){add(c.mac)});"
"    var gb=document.getElementById('guest-body');"
"    if(!order.length){"
"      /* No identity, so there is nothing below to manage. Hide the line that"
"         offers to manage it, or the two hints contradict each other. */"
"      if(gb){gb.style.display='none'}"
"      box.innerHTML='<div class=\"hint\">'+t('guest_noident')+'</div>';"
"      return;"
"    }"
"    if(gb){gb.style.display='block'}"
"    var h=\"<h2>\"+t('guest_devices')+\"</h2>\";"
"    order.forEach(function(mac){"
"      var id=mac.replace(/:/g,'');"
"      var d=rec[mac]||{};"
"      var c=live[mac];"
"      var isSelf=(mac===me);"
"      /* A device always may edit itself. It has no record in /api/devices"
"         unless it is flagged or owned, so d.mine alone leaves a plain guest"
"         looking at its own card with no form. The write guards agree: a caller"
"         may touch its own MAC. */"
"      var editable=isSelf||!!d.mine;"
"      var claimable=!!d.claimable;"
"      var lease=null;(L.leases||[]).forEach(function(x){if(x.mac===mac){lease=x}});"
"      var rule=null;(R.rules||[]).forEach(function(x){if(x.mac===mac){rule=x}});"
"      var head=(c&&c.host)?c.host:t('unknown');"
"      h+=\"<div style='border:1px solid #e2e8f0;border-radius:8px;margin-bottom:12px;overflow:hidden'>\";"
"      h+=\"<div style='padding:10px 14px;background:#f8fafc;display:flex;align-items:center;gap:8px'>\";"
"      h+=\"<div style='flex:1;min-width:0'>\""
"        +\"<div style='display:flex;justify-content:space-between;align-items:center;gap:8px'>\""
"        +\"<span class='mono' style='font-size:12px;overflow:hidden;text-overflow:ellipsis'>\"+mac+\"</span>\""
"        +\"<span style='font-size:12px;white-space:nowrap;color:\"+(c?'#15803d':'#94a3b8')+\"'>\""
"        +(c?(c.ip||'?'):t('device_offline'))+\"</span></div>\""
"        +\"<div style='font-size:12px;color:#475569;margin-top:3px;overflow:hidden;text-overflow:ellipsis'>\"+head"
"        +(isSelf?(' &middot; <b>'+t('your_device')+'</b>'):'')"
"        +(claimable?(' &middot; '+t('claimable_hint')):'')+\"</div>\""
"        +\"</div>\";"
"      if(editable){"
"        h+=\"<button class='refresh-btn' style='flex:0 0 auto' onclick='toggleGuest(\\\"\"+id+\"\\\")'>&#9881; \"+t('cfg_btn')+\"</button>\";"
"      }else if(claimable){"
"        /* Claiming is one action, so it gets a button rather than a card. */"
"        h+=\"<button class='refresh-btn' style='flex:0 0 auto' onclick='aclClaim(\\\"\"+mac+\"\\\")'>\"+t('claim_btn')+\"</button>\";"
"      }"
"      h+=\"</div>\";"
"      if(editable){"
"        /* The card is a SIBLING of the bar, not its child: nested inside a"
"           clickable bar, a click on a card button bubbles up and toggles the"
"           card shut. The admin client row is built this way for the same"
"           reason. */"
"        h+=\"<div id='cd-\"+id+\"' style='display:none'>\";"
"        h+=deviceEditHtml(id,mac,lease,rule,L,c?c.ip:'');"
"        /* An owned IoT device: its holder may hand it back. */"
"        if(d.iot&&d.owner===me&&!isSelf){"
"          h+=\"<div style='padding:0 14px 12px;background:#f8fafc'>\""
"            +\"<button class='refresh-btn' style='width:100%' onclick='aclClaim(\\\"\"+mac+\"\\\")'>\""
"            +t('release_btn')+\"</button></div>\";"
"        }"
"        h+=\"</div>\";"
"      }"
"      h+=\"</div>\";"
"    });"
"    box.innerHTML=h;"
"    order.forEach(function(mac){"
"      var id=mac.replace(/:/g,'');"
"      var ms=document.getElementById('cd-mode-'+id);"
"      if(ms){wirePresets(ms,document.getElementById('cd-preset-'+id),"
"                         document.getElementById('cd-addr-'+id))}"
"    });"
"    /* Re-open and reload whichever card was expanded before, so a save does not"
"       silently collapse it and hide the result message. */"
"    if(openGuestId){"
"      var el=document.getElementById('cd-'+openGuestId);"
"      if(el){"
"        el.style.display='block';"
"        if(msg){cdMsg(openGuestId,msg.ok,msg.txt)}"
"      }else{"
"        openGuestId=null;"
"      }"
"    }"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"var openGuestId=null;"
"function toggleGuest(id){"
"  var el=document.getElementById('cd-'+id);"
"  if(!el){return}"
"  if(el.style.display==='block'){openGuestId=null;el.style.display='none';return}"
"  openGuestId=id;"
"  el.style.display='block';"
"}"
"/* A device card is drawn in two places - the admin Clients tab and the guest"
"   view. A save has to re-render whichever one is on screen; refreshing the other"
"   writes the result into hidden DOM and the user sees nothing at all. */"
"function isGuestView(){"
"  return document.getElementById('guest-view').style.display!=='none';"
"}"
"function refreshDeviceView(id,msg){"
"  if(isGuestView()){openGuestId=id;loadGuestView(msg);return}"
"  openClientId=id;keepMsg=msg;loadClients();"
"}"
"function cdMsg(id,ok,txt){"
"  var m=document.getElementById('cd-msg-'+id);"
"  if(m){m.innerHTML='<span style=\"color:'+(ok?'#15803d':'#b91c1c')+'\">'+(ok?t('saved'):t('rejected')+': '+txt)+'</span>'}"
"}"
"function cdSaveLease(mac,id){"
"  var ip=document.getElementById('cd-ip-'+id).value.trim();"
"  if(!ip){keepMsg={ok:false,txt:t('enter_both')};cdMsg(id,false,t('enter_both'));return}"
"  fetch('/lease/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&ip='+encodeURIComponent(ip)})"
"  .then(function(r){return r.text().then(function(x){"
"    refreshDeviceView(id,{ok:r.ok,txt:x});   /* reopens the card and shows x */"
"    loadLeases();"
"  })});"
"}"
"function cdDelLease(mac,id){"
"  if(!confirm(t('confirm_lease')+' '+mac+' ?')){return}"
"  fetch('/lease/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})"
"  .then(function(){refreshDeviceView(id);loadLeases()});"
"}"
"function cdSaveRule(mac,id){"
"  var mode=document.getElementById('cd-mode-'+id).value;"
"  var addr=document.getElementById('cd-addr-'+id).value.trim();"
"  if(!addr){keepMsg={ok:false,txt:t('enter_both')};cdMsg(id,false,t('enter_both'));return}"
"  fetch('/dnsrule/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&mode='+mode+'&addr='+encodeURIComponent(addr)})"
"  .then(function(r){return r.text().then(function(x){"
"    refreshDeviceView(id,{ok:r.ok,txt:x});"
"    loadDnsRules();"
"  })});"
"}"
"function cdDelRule(mac,id){"
"  if(!confirm(t('confirm_rule')+' '+mac+' ?')){return}"
"  fetch('/dnsrule/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})"
"  .then(function(){refreshDeviceView(id);loadDnsRules()});"
"}"
"function loadSsid(){return fetch('/api/ssid').then(function(r){return r.json()}).then(function(d){document.getElementById('ssid-name').value=d.ssid}).catch(function(){})}"
"function saveSsid(){"
"  var v=document.getElementById('ssid-name').value.trim();"
"  if(!v){alert(t('enter_both'));return}"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/setssid',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'ssid='+encodeURIComponent(v)})"
"  .then(function(r){return r.text().then(function(x){"
"    document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):(t('rejected')+': '+x);"
"  })})"
"  .finally(function(){btn.innerText=t('save_name_btn')});"
"}"
"function loadAuth(){"
"  return fetch('/api/webauth').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('web-user').value=d.user;"
"    document.getElementById('auth-state').innerHTML=d.enabled?t('auth_on'):('<b>'+t('auth_open')+'</b>');"
"    document.getElementById('auth-state').style.color=d.enabled?'#15803d':'#b91c1c';"
"  }).catch(function(){});"
"}"
"function savePanelAuth(){"
"  var u=document.getElementById('web-user').value.trim(),p=document.getElementById('web-pass').value;"
"  var m=document.getElementById('settings-msg');"
"  fetch('/setwebauth',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'user='+encodeURIComponent(u)+'&pass='+encodeURIComponent(p)})"
"  .then(function(r){return r.text().then(function(x){m.innerHTML=r.ok?t('saved'):(t('rejected')+': '+x)});"
"  }).finally(function(){document.getElementById('web-pass').value='';loadAuth()});"
"}"
"function loadDoh(){"
"  return fetch('/api/dohurl').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('doh-url').value=d.url;"
"    var s=document.getElementById('doh-state');"
"    s.innerHTML=t('sec_doh')+': <b>'+dohText(d.mode)+'</b>';"
"    s.style.color=(d.mode==='doh')?'#15803d':((d.mode==='idle')?'#64748b':'#b45309');"
"    document.getElementById('doh-suggest').innerHTML=\"CN: <b>223.5.5.5</b> / <b>dns.alidns.com</b> / <b>1.12.12.12</b> / <b>doh.pub</b><br>1.1.1.1 / 8.8.8.8 / 9.9.9.9\";"
"  }).catch(function(){});"
"}"
"function saveDoh(){"
"  var u=document.getElementById('doh-url').value.trim();"
"  if(u.indexOf('https://')!==0){alert('https://');return}"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/setdohurl',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(u)})"
"  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):t('rejected')})"
"  .finally(function(){btn.innerText=t('save_resolver_btn');loadDoh()});"
"}"
"function loadRadio(){"
"  return fetch('/api/radio').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('bw-sel').value=(d.bw==='HT20')?'20':'40';"
"    document.getElementById('radio-state').innerHTML=d.country+' &middot; CH '+d.ch_min+'-'+d.ch_max+' &middot; <b>'+d.txpower_dbm+' dBm</b>';"
"  }).catch(function(){});"
"}"
"function saveRadio(){"
"  var bw=document.getElementById('bw-sel').value;"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/setradio',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'bw='+bw})"
"  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('applied'):t('failed')})"
"  .finally(function(){btn.innerText=t('apply_btn');loadRadio()});"
"}"
"var DNS_PRESETS={"
" doh:["
"  {cn:1,name:'\\u963f\\u91cc 223.5.5.5',addr:'https://223.5.5.5/dns-query'},"
"  {cn:1,name:'\\u963f\\u91cc dns.alidns.com',addr:'https://dns.alidns.com/dns-query'},"
"  {cn:1,name:'\\u817e\\u8baf 1.12.12.12',addr:'https://1.12.12.12/dns-query'},"
"  {cn:1,name:'\\u817e\\u8baf doh.pub',addr:'https://doh.pub/dns-query'},"
"  {cn:0,name:'Cloudflare 1.1.1.1',addr:'https://1.1.1.1/dns-query'},"
"  {cn:0,name:'Google dns.google',addr:'https://dns.google/dns-query'},"
"  {cn:0,name:'Quad9 9.9.9.9',addr:'https://9.9.9.9/dns-query'}"
" ],"
" dot:["
"  {cn:1,name:'\\u963f\\u91cc 223.5.5.5',addr:'223.5.5.5'},"
"  {cn:1,name:'\\u963f\\u91cc 223.6.6.6',addr:'223.6.6.6'},"
"  {cn:1,name:'\\u817e\\u8baf 1.12.12.12',addr:'1.12.12.12'},"
"  {cn:1,name:'\\u817e\\u8baf 120.53.53.53',addr:'120.53.53.53'},"
"  {cn:0,name:'Cloudflare 1.1.1.1',addr:'1.1.1.1'},"
"  {cn:0,name:'Google 8.8.8.8',addr:'8.8.8.8'},"
"  {cn:0,name:'Quad9 9.9.9.9',addr:'9.9.9.9'}"
" ],"
" dns:["
"  {cn:1,name:'\\u963f\\u91cc 223.5.5.5',addr:'223.5.5.5'},"
"  {cn:1,name:'\\u963f\\u91cc 223.6.6.6',addr:'223.6.6.6'},"
"  {cn:1,name:'DNSPod 119.29.29.29',addr:'119.29.29.29'},"
"  {cn:1,name:'114DNS 114.114.114.114',addr:'114.114.114.114'},"
"  {cn:1,name:'\\u767e\\u5ea6 180.76.76.76',addr:'180.76.76.76'},"
"  {cn:0,name:'Cloudflare 1.1.1.1',addr:'1.1.1.1'},"
"  {cn:0,name:'Google 8.8.8.8',addr:'8.8.8.8'}"
" ]"
"};"
"/* Rebuild a preset dropdown for the given protocol. Grouped, and the foreign"
"   group is labelled as unreachable here - verified by measurement, not assumed:"
"   TCP 443 and 853 to those addresses are filtered on this network while plain"
"   DNS to them passes. */"
"function fillPresets(sel,mode){"
"  if(!sel){return}"
"  var list=DNS_PRESETS[mode]||[];"
"  var h=\"<option value=''>\"+t('preset_choose')+\"</option>\";"
"  var groups={1:[],0:[]};"
"  list.forEach(function(p){groups[p.cn].push(p)});"
"  /* Plain DNS to foreign servers is NOT filtered - only TCP 443 and 853 are - so"
"     the foreign group must not claim \"unreachable\" in that mode or it would steer"
"     the user away from servers that work. */"
"  var foreignKey=(mode==='dns')?'preset_foreign_plain':'preset_foreign';"
"  [[1,'preset_cn'],[0,foreignKey]].forEach(function(g){"
"    if(!groups[g[0]].length){return}"
"    h+=\"<optgroup label='\"+t(g[1])+\"'>\";"
"    groups[g[0]].forEach(function(p){"
"      h+=\"<option value='\"+p.addr+\"'>\"+p.name+\"</option>\";"
"    });"
"    h+=\"</optgroup>\";"
"  });"
"  sel.innerHTML=h;"
"}"
"/* Wire a mode select, a preset select and an address input together. */"
"function wirePresets(modeSel,presetSel,addrInput){"
"  if(!modeSel||!presetSel||!addrInput){return}"
"  function sync(){ fillPresets(presetSel,modeSel.value) }"
"  modeSel.addEventListener('change',function(){ sync() });"
"  presetSel.addEventListener('change',function(){"
"    if(presetSel.value){ addrInput.value=presetSel.value }"
"  });"
"  sync();"
"}"
"function loadDnsRules(){"
"  var box=document.getElementById('dr-list');"
"  return fetch('/api/dnsrules').then(function(r){return r.json()}).then(function(d){"
"    if(!d.rules.length){box.innerHTML='<div class=\"loading\">'+t('no_rules')+'</div>';return}"
"    var h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.rules.forEach(function(r){"
"      h+=\"<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>\""
"        +\"<span class='mono' style='font-size:11px'><b>\"+r.mode+\"</b> \"+r.addr+\"<br><span style='color:#64748b'>\"+r.mac+\"</span></span>\""
"        +\"<button class='refresh-btn' onclick='delDnsRule(\\\"\"+r.mac+\"\\\")'>\"+t('delete')+\"</button></div></div>\";"
"    });"
"    box.innerHTML=h+'</div>';"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"function addDnsRule(){"
"  var mac=document.getElementById('dr-mac').value.trim(),mode=document.getElementById('dr-mode').value,addr=document.getElementById('dr-addr').value.trim();"
"  var m=document.getElementById('dr-msg');"
"  if(!mac||!addr){m.innerHTML='<span style=\"color:#b45309\">'+t('enter_both')+'</span>';return}"
"  fetch('/dnsrule/set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&mode='+mode+'&addr='+encodeURIComponent(addr)})"
"  .then(function(r){return r.text().then(function(x){"
"    m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>'):('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"    if(r.ok){document.getElementById('dr-mac').value='';document.getElementById('dr-addr').value=''}"
"    loadDnsRules();"
"  })});"
"}"
"function delDnsRule(mac){"
"  if(!confirm(t('confirm_rule')+' '+mac+' ?')){return}"
"  fetch('/dnsrule/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadDnsRules()});"
"}"
"function runDnsTest(){"
"  var m=document.getElementById('dr-msg');"
"  m.innerHTML='<span style=\"color:#64748b\">'+t('testing')+'</span>';"
"  fetch('/api/dnstest').then(function(r){return r.json()}).then(function(d){"
"    var h=\"<div class='testout'><b>default</b> \"+d.default.mode+' '+d.default.addr+'<br>&nbsp;&nbsp;'+d.default.result+'<br>';"
"    d.rules.forEach(function(r){h+='<b>'+r.mac+'</b> '+r.mode+' '+r.addr+'<br>&nbsp;&nbsp;'+r.result+'<br>'});"
"    m.innerHTML=h+'</div>';"
"  }).catch(function(){m.innerHTML='<span style=\"color:#b91c1c\">'+t('test_failed')+'</span>'});"
"}"
"function loadLeases(){"
"  var box=document.getElementById('lease-list');"
"  return fetch('/api/leases').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('lease-msg').innerHTML=d.pool_known?(t('pool_free')+' <b>'+d.pool_first+'-'+d.pool_last+'</b> '+t('pool_in_use')):'';"
"    if(!d.leases.length){box.innerHTML='<div class=\"loading\">'+t('no_leases')+'</div>';return}"
"    var h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.leases.forEach(function(l){"
"      h+=\"<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>\""
"        +\"<span class='mono' style='font-size:12px'><b>\"+l.ip+\"</b> &larr; \"+l.mac+\"</span>\""
"        +\"<button class='refresh-btn' onclick='delLease(\\\"\"+l.mac+\"\\\")'>\"+t('delete')+\"</button></div></div>\";"
"    });"
"    box.innerHTML=h+'</div>';"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"function addLease(){"
"  var mac=document.getElementById('lease-mac').value.trim(),ip=document.getElementById('lease-ip').value.trim();"
"  var m=document.getElementById('lease-msg');"
"  if(!mac||!ip){m.innerHTML='<span style=\"color:#b45309\">'+t('enter_both')+'</span>';return}"
"  fetch('/lease/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)+'&ip='+encodeURIComponent(ip)})"
"  .then(function(r){return r.text().then(function(x){"
"    m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+' '+t('lease_note')+'</span>'):('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"    if(r.ok){document.getElementById('lease-mac').value='';document.getElementById('lease-ip').value=''}"
"    loadLeases();"
"  })});"
"}"
"function delLease(mac){"
"  if(!confirm(t('confirm_lease')+' '+mac+' ?')){return}"
"  fetch('/lease/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadLeases()});"
"}"
"function loadPortmaps(){"
"  var box=document.getElementById('pm-list');"
"  return fetch('/api/portmaps').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('pm-note').innerHTML=d.external?(t('fwd_external')+' <b>'+d.external+'</b>'):t('fwd_no_ext');"
"    if(!d.rules.length){box.innerHTML='<div class=\"loading\">'+t('no_forwards')+'</div>';return}"
"    var h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.rules.forEach(function(r){"
"      h+=\"<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>\""
"        +\"<span class='mono' style='font-size:12px'><b>\"+r.proto+' '+r.mport+\"</b> &rarr; \"+r.daddr+':'+r.dport+\"</span>\""
"        +\"<button class='refresh-btn' onclick='delPortmap(\\\"\"+r.proto+\"\\\",\"+r.mport+\")'>\"+t('delete')+\"</button></div></div>\";"
"    });"
"    box.innerHTML=h+'</div>';"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"function addPortmap(){"
"  var p=document.getElementById('pm-proto').value,mp=document.getElementById('pm-mport').value.trim();"
"  var da=document.getElementById('pm-daddr').value.trim(),dp=document.getElementById('pm-dport').value.trim();"
"  var m=document.getElementById('pm-msg');"
"  if(!mp||!da||!dp){m.innerHTML='<span style=\"color:#b45309\">'+t('enter_both')+'</span>';return}"
"  fetch('/portmap/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+p+'&mport='+encodeURIComponent(mp)+'&daddr='+encodeURIComponent(da)+'&dport='+encodeURIComponent(dp)})"
"  .then(function(r){return r.text().then(function(x){"
"    m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>'):('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"    if(r.ok){document.getElementById('pm-mport').value='';document.getElementById('pm-daddr').value='';document.getElementById('pm-dport').value=''}"
"    loadPortmaps();"
"  })});"
"}"
"function delPortmap(proto,mport){"
"  if(!confirm(t('confirm_fwd')+' '+proto+' '+mport+' ?')){return}"
"  fetch('/portmap/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'proto='+proto+'&mport='+mport}).then(function(){loadPortmaps()});"
"}"
"function loadApCfg(){"
"  return fetch('/api/apcfg').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('ap-hidden').value=d.hidden?'1':'0';"
"    document.getElementById('ap-maxconn').value=d.maxconn;"
"    document.getElementById('ap-txpower').value=d.txpower_dbm;"
"  }).catch(function(){});"
"}"
"function saveApCfg(){"
"  var h=document.getElementById('ap-hidden').value;"
"  var c=document.getElementById('ap-maxconn').value.trim();"
"  var p=document.getElementById('ap-txpower').value.trim();"
"  var m=document.getElementById('settings-msg');"
"  if(!c||!p){m.innerHTML='<span style=\"color:#b45309\">'+t('enter_both')+'</span>';return}"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/setapcfg',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hidden='+h+'&maxconn='+encodeURIComponent(c)+'&txpower='+encodeURIComponent(p)})"
"  .then(function(r){return r.text().then(function(x){m.innerHTML=r.ok?t('applied'):(t('rejected')+': '+x)})})"
"  .finally(function(){btn.innerText=t('save_apctl_btn');loadApCfg()});"
"}"
"function loadDevPolicy(){"
"  return fetch('/api/devices').then(function(r){return r.json()}).then(function(d){"
"    document.getElementById('pol-claim').checked=!!d.guest_claim;"
"    document.getElementById('pol-clrvis').checked=!!d.clear_on_visit;"
"  }).catch(function(){});"
"}"
"function saveDevPolicy(){"
"  var m=document.getElementById('settings-msg');"
"  var c=document.getElementById('pol-claim').checked?'1':'0';"
"  var v=document.getElementById('pol-clrvis').checked?'1':'0';"
"  fetch('/setdevpolicy',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'claim='+c+'&clearvisit='+v})"
"  .then(function(r){ m.innerHTML=r.ok?t('saved'):t('failed'); loadDevPolicy() })"
"  .catch(function(){ m.innerHTML=t('failed') });"
"}"
"function aclClaim(mac){"
"  var id=mac.replace(/:/g,'');"
"  fetch('/claim',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'mac='+encodeURIComponent(mac)})"
"  .then(function(r){ return r.text().then(function(x){"
"    if(!r.ok){ alert(t('rejected')+': '+x) }"
"    /* Claiming makes the device editable, so open its card and say so. A"
"       release leaves it claimable with no card, where there is nowhere to put"
"       the message - the row changing back is the feedback. */"
"    openGuestId=id;"
"    loadGuestView(r.ok?{ok:true,txt:t('saved')}:null);"
"  }) });"
"}"
"function loadAcl(){"
"  var box=document.getElementById('acl-list');"
"  return fetch('/api/acl').then(function(r){return r.json()}).then(function(d){"
"    var st=document.getElementById('acl-state');"
"    st.innerHTML=d.enabled?('<b>'+t('acl_state_on')+'</b>'):t('acl_state_off');"
"    st.style.color=d.enabled?'#b45309':'#64748b';"
"    document.getElementById('acl-toggle-btn').innerHTML=d.enabled?t('acl_disable_btn'):t('acl_enable_btn');"
"    document.getElementById('acl-toggle-btn').className='btn small'+(d.enabled?' danger':'');"
"    if(!d.macs.length){box.innerHTML='<div class=\"loading\">'+t('acl_empty')+'</div>';return}"
"    var h='<div class=\"network-list\" style=\"max-height:none\">';"
"    d.macs.forEach(function(m){"
"      h+=\"<div class='network-item' style='cursor:default'><div style='display:flex;justify-content:space-between;align-items:center;width:100%'>\""
"        +\"<span class='mono' style='font-size:12px'>\"+m+\"</span>\""
"        +\"<button class='refresh-btn' onclick='aclDel(\\\"\"+m+\"\\\")'>\"+t('delete')+\"</button></div></div>\";"
"    });"
"    box.innerHTML=h+'</div>';"
"  }).catch(function(){box.innerHTML='<div class=\"loading\">'+t('failed_load')+'</div>'});"
"}"
"function aclAdd(){"
"  var mac=document.getElementById('acl-mac').value.trim(),m=document.getElementById('acl-msg');"
"  if(!mac){m.innerHTML='<span style=\"color:#b45309\">'+t('enter_both')+'</span>';return}"
"  fetch('/acl/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)})"
"  .then(function(r){return r.text().then(function(x){"
"    m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>'):('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"    if(r.ok){document.getElementById('acl-mac').value=''}"
"    loadAcl();"
"  })});"
"}"
"function aclDel(mac){"
"  fetch('/acl/del',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+encodeURIComponent(mac)}).then(function(){loadAcl()});"
"}"
"function aclToggle(){"
"  fetch('/api/acl').then(function(r){return r.json()}).then(function(d){"
"    var on=d.enabled?'0':'1',m=document.getElementById('acl-msg');"
"    fetch('/acl/enable',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'on='+on})"
"    .then(function(r){return r.text().then(function(x){"
"      m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>'):('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"      loadAcl();"
"    })});"
"  });"
"}"
"function loadHostname(){return fetch('/api/hostname').then(function(r){return r.json()}).then(function(d){document.getElementById('mdns-name').value=d.hostname}).catch(function(){})}"
"function saveHostname(){"
"  var v=document.getElementById('mdns-name').value.trim();"
"  if(!v){alert(t('enter_both'));return}"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/sethostname',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'hostname='+encodeURIComponent(v)})"
"  .then(function(r){return r.text().then(function(x){document.getElementById('settings-msg').innerHTML=r.ok?t('saved'):(t('rejected')+': '+x)})})"
"  .finally(function(){btn.innerText=t('save_mdns_btn')});"
"}"
"/* Installed build, and which OTA slot it is running from. The slot is what tells"
"   you an upload actually switched slots rather than silently doing nothing. */"
"/* Substitutes {name} placeholders. Applied to the result of t() rather than"
"   wrapped around it, so the generator still sees an ordinary lookup call and"
"   checks the key exists in both dictionaries. (Wrapping would hide the key from"
"   that scan, and the key check does not strip comments, so do not spell a"
"   literal lookup call out in prose either - it gets counted as a reference.) */"
"function sub(s,vars){"
"  if(!vars){return s}"
"  for(var p in vars){s=s.split('{'+p+'}').join(vars[p])}"
"  return s;"
"}"
"/* The device only ever sends fixed strings here, so this is belt and braces;"
"   it costs nothing and keeps the rule \"never interpolate a reply into HTML\""
"   from depending on that staying true. */"
"function esc(s){"
"  return String(s==null?'':s)"
"    .split('&').join('&amp;')"
"    .split('<').join('&lt;')"
"    .split('>').join('&gt;');"
"}"
"function agoText(secs){"
"  if(!secs||secs<=0){return t('ota_never')}"
"  if(secs<3600){return sub(t('ota_ago_min'),{n:Math.max(1,Math.round(secs/60))})}"
"  if(secs<86400){return sub(t('ota_ago_hour'),{n:Math.round(secs/3600)})}"
"  return sub(t('ota_ago_day'),{n:Math.round(secs/86400)});"
"}"
"/* One request feeds the whole firmware block: version, slot, settings and the"
"   update state. */"
"function loadUpdateInfo(){"
"  return fetch('/api/update').then(function(r){return r.json()}).then(function(d){"
"    var v=document.getElementById('fw-version');"
"    if(v){v.textContent=(d.running||'?')}"
"    var s=document.getElementById('fw-slot');"
"    if(s){s.textContent=(d.slot?t('fw_slot')+' '+d.slot:'')}"
"    var h=document.getElementById('ota-hours');"
"    if(h){h.value=String(d.interval_hours)}"
"    var a=document.getElementById('ota-auto');"
"    /* A development build keeps checking and installing by hand - that is how"
"       the update path gets tested - and loses only the automatic part. So the"
"       two controls that describe automatic behaviour are disabled and explained"
"       rather than the whole section disappearing. */"
"    var dev=!d.release_build;"
"    var devNote=document.getElementById('ota-devb');"
"    if(devNote){devNote.style.display=dev?'block':'none'}"
"    var h=document.getElementById('ota-hours');"
"    if(h){h.disabled=dev}"
""
"    if(a){a.checked=!!d.auto_install; a.disabled=dev}"
"    var br=document.getElementById('ota-buildrepo');"
"    if(br){br.value=d.build_repo||t('ota_repo_unknown')}"
"    var u=document.getElementById('ota-url');"
"    /* Never overwrite what the user is in the middle of typing. */"
"    if(u&&document.activeElement!==u){u.value=d.url||''}"
"    renderOtaState(d);"
"  }).catch(function(){});"
"}"
"function renderOtaState(d){"
"  var st=document.getElementById('ota-status');"
"  var bar=document.getElementById('ota-bar');"
"  var inst=document.getElementById('ota-install-btn');"
"  var btn=document.getElementById('ota-check-btn');"
"  if(!st){return}"
"  var line=t('ota_lastcheck')+': '+agoText(d.last_check_ago);"
"  var busy=(d.state==='checking'||d.state==='downloading'||d.state==='installing');"
"  if(btn){btn.disabled=busy}"
"  if(inst){inst.style.display=(d.state==='available')?'inline-block':'none'}"
"  if(bar){"
"    var show=(d.state==='downloading'||d.state==='installing');"
"    bar.style.display=show?'block':'none';"
"    bar.value=d.progress||0;"
"  }"
"  if(d.state==='checking'){st.innerHTML='<span style=\"color:#64748b\">'+t('ota_checking')+'...</span>'}"
"  else if(d.state==='downloading'){st.innerHTML='<span style=\"color:#1d4ed8\">'+t('ota_downloading')+' '+(d.progress||0)+'%</span>'}"
"  else if(d.state==='installing'){st.innerHTML='<span style=\"color:#b45309\">'+t('ota_installing')+'</span>'}"
"  else if(d.state==='available'){st.innerHTML='<span style=\"color:#15803d\"><b>'+sub(t('ota_available'),{v:d.latest})+'</b></span>'}"
"  else if(d.state==='uptodate'){st.innerHTML='<span style=\"color:#15803d\">'+t('ota_uptodate')+'</span>'}"
"  else if(d.state==='error'){st.innerHTML='<span style=\"color:#b91c1c\">'+t('ota_failed')+': '+esc(d.error)+'</span>'}"
"  else{st.innerHTML='<span style=\"color:#64748b\">'+line+'</span>'}"
"  /* Keep the \"last checked\" line visible alongside a result, except when the"
"     result already carries the useful information. */"
"  if(d.state!=='idle'&&d.state!=='checking'&&line&&d.last_check_ago){st.innerHTML+=' <span style=\"color:#94a3b8\">('+line+')</span>'}"
"  if(busy){watchOta()}"
"}"
"/* Poll while something is in flight. Failures are ignored on purpose: writing"
"   flash disables the cache, so the web server can hitch mid-download and a"
"   dropped poll means nothing. */"
"var otaWatch=null;"
"function watchOta(){"
"  if(otaWatch){return}"
"  otaWatch=setInterval(function(){"
"    fetch('/api/update',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){"
"      renderOtaState(d);"
"      if(d.state!=='checking'&&d.state!=='downloading'&&d.state!=='installing'){"
"        clearInterval(otaWatch);otaWatch=null;"
"        /* A reboot follows a successful install; wait it out and say so. */"
"        if(d.state==='idle'&&d.running){waitForReboot()}"
"      }"
"    }).catch(function(){});"
"  },2000);"
"}"
"function saveOtaCfg(){"
"  var m=document.getElementById('ota-msg');"
"  var h=document.getElementById('ota-hours').value;"
"  var a=document.getElementById('ota-auto').checked?'1':'0';"
"  var u=document.getElementById('ota-url').value.trim();"
"  fetch('/setotacfg',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'hours='+encodeURIComponent(h)+'&auto='+a+'&url='+encodeURIComponent(u)})"
"  .then(function(r){return r.text().then(function(x){"
"    m.innerHTML=r.ok?('<span style=\"color:#15803d\">'+t('saved')+'</span>')"
"                    :('<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>');"
"    loadUpdateInfo();"
"  })}).catch(function(){m.innerHTML=t('failed')});"
"}"
"function otaCheckNow(){"
"  var m=document.getElementById('ota-msg');"
"  m.innerHTML='';"
"  fetch('/ota/check',{method:'POST'}).then(function(){watchOta()}).catch(function(){});"
"}"
"function otaInstallNow(){"
"  if(!confirm(t('ota_install_confirm'))){return}"
"  fetch('/ota/install',{method:'POST'}).then(function(){watchOta()}).catch(function(){});"
"}"
"function loadFwInfo(){"
"  /* Kept as the name the settings chain calls; the data now comes from"
"     /api/update so a page load makes one request, not two. */"
"  return loadUpdateInfo();"
"}"
"function devCmdText(token){"
"  /* The header has to be spelled out: the token is not a cookie, so a plain"
"     browser URL will not work and the example is the documentation. */"
"  var u=location.protocol+'//'+location.host+'/ota';"
"  return 'curl -X POST --data-binary @embedwrt.bin -H \"Content-Type: application/octet-stream\"'"
"    +' -H \"X-OTA-Token: '+(token||'<token>')+'\" '+u;"
"}"
"function renderDevMode(d){"
"  /* Note: never name a local 't' here. t() is the translation helper, and"
"     shadowing it turns every later lookup into a call on a DOM element -"
"     which fails at runtime, not at generation time. */"
"  var on=document.getElementById('dev-on');"
"  if(on){on.checked=!!d.enabled}"
"  var tok=document.getElementById('dev-token');"
"  if(tok){tok.value=d.token||''}"
"  var c=document.getElementById('dev-cmd');"
"  if(c){c.value=devCmdText(d.token)}"
"  var m=document.getElementById('dev-msg');"
"  if(m&&!m.innerHTML){m.innerHTML=d.enabled?t('dev_on'):t('dev_off')}"
"  var r=document.getElementById('dev-regen');"
"  if(r){r.disabled=!d.enabled}"
"}"
"function loadDevMode(){"
"  return fetch('/api/devmode').then(function(r){return r.json()}).then(function(d){"
"    renderDevMode(d);"
"  }).catch(function(){});"
"}"
"function saveDevMode(){"
"  var m=document.getElementById('dev-msg');"
"  var on=document.getElementById('dev-on').checked?'1':'0';"
"  fetch('/setdevmode',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'on='+on})"
"  .then(function(r){return r.text().then(function(x){"
"    if(!r.ok){m.innerHTML='<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>';return}"
"    m.innerHTML='<span style=\"color:#15803d\">'+t('saved')+'</span>';"
"    loadDevMode();"
"  })}).catch(function(){m.innerHTML=t('failed')});"
"}"
"function regenDevToken(){"
"  var m=document.getElementById('dev-msg');"
"  if(!document.getElementById('dev-on').checked){m.innerHTML='<span style=\"color:#b45309\">'+t('dev_need_on')+'</span>';return}"
"  if(!confirm(t('dev_regen_btn')+'?')){return}"
"  fetch('/setdevmode',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
"        body:'regen=1'})"
"  .then(function(r){return r.text().then(function(x){"
"    if(!r.ok){m.innerHTML='<span style=\"color:#b91c1c\">'+t('rejected')+': '+x+'</span>';return}"
"    m.innerHTML='<span style=\"color:#15803d\">'+t('dev_token_changed')+'</span>';"
"    loadDevMode();"
"  })}).catch(function(){m.innerHTML=t('failed')});"
"}"
"/* Waits out the restart, then reports. The delay before the first poll matters:"
"   the response to the upload arrives while the OLD firmware is still running and"
"   answering normally, so polling straight away would succeed against the old"
"   build and reload the page too early. */"
"function waitForReboot(){"
"  var m=document.getElementById('fw-msg');"
"  var tries=0;"
"  function poll(){"
"    tries++;"
"    fetch('/api/session',{cache:'no-store'}).then(function(r){"
"      if(r.ok){ m.innerHTML='<span style=\"color:#15803d\">'+t('fw_relogin')+'</span>';"
"                setTimeout(function(){location.reload()},1500); return }"
"      retry();"
"    }).catch(retry);"
"  }"
"  function retry(){"
"    if(tries>20){ m.innerHTML='<span style=\"color:#b45309\">'+t('fw_noback')+'</span>'; return }"
"    setTimeout(poll,2000);"
"  }"
"  m.innerHTML=t('fw_wait');"
"  setTimeout(poll,8000);"
"}"
"function otaUpload(){"
"  var inp=document.getElementById('fw-file');"
"  var m=document.getElementById('fw-msg');"
"  var bar=document.getElementById('fw-bar');"
"  var btn=document.getElementById('fw-btn');"
"  if(!inp||!inp.files||!inp.files.length){ m.innerHTML='<span style=\"color:#b45309\">'+t('fw_nofile')+'</span>'; return }"
"  var f=inp.files[0];"
"  if(!confirm(t('fw_confirm')+' '+f.name+' ('+Math.round(f.size/1024)+' KB)')){return}"
"  /* XMLHttpRequest rather than fetch: fetch cannot report upload progress. The"
"     File object is sent as the raw body, so the device needs no form parsing. */"
"  var xhr=new XMLHttpRequest();"
"  xhr.open('POST','/ota');"
"  xhr.setRequestHeader('Content-Type','application/octet-stream');"
"  btn.disabled=true;"
"  btn.innerText=t('fw_uploading');"
"  bar.style.display='block';"
"  bar.value=0;"
"  xhr.upload.onprogress=function(e){"
"    if(e.lengthComputable){"
"      var pct=Math.round(e.loaded*100/e.total);"
"      bar.value=pct;"
"      m.innerHTML=t('fw_uploading')+' '+pct+'%';"
"    }"
"  };"
"  xhr.onload=function(){"
"    if(xhr.status>=200&&xhr.status<300){"
"      bar.value=100;"
"      m.innerHTML='<span style=\"color:#15803d\">'+t('fw_ok')+'</span>';"
"      waitForReboot();"
"    }else{"
"      btn.disabled=false;"
"      btn.innerText=t('fw_upload_btn');"
"      bar.style.display='none';"
"      /* textContent, not innerHTML: this is whatever the device sent back. */"
"      m.innerHTML='<span style=\"color:#b91c1c\">'+t('fw_failed')+': </span>';"
"      m.appendChild(document.createTextNode(xhr.responseText||''));"
"    }"
"  };"
"  /* A network error here usually means the device restarted before it could"
"     reply, which is a success - so follow the same wait path. */"
"  xhr.onerror=function(){ waitForReboot() };"
"  xhr.send(f);"
"}"
"function changePass(){"
"  var pass=document.getElementById('new-pass').value;"
"  if(pass.length<8){alert(t('pass_short'));return}"
"  var btn=event.target;btn.innerText='...';"
"  fetch('/setpass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'pass='+encodeURIComponent(pass)})"
"  .then(function(r){document.getElementById('settings-msg').innerHTML=r.ok?t('pass_changed'):t('pass_failed')})"
"  .finally(function(){btn.innerText=t('change_pass_btn')});"
"}"
"function resetAP(){"
"  if(!confirm(t('reset_confirm'))){return}"
"  fetch('/resetpass',{method:'POST'}).then(function(r){"
"    if(r.ok){alert(t('reset_done'));location.reload()}else{alert(t('reset_failed'))}"
"  });"
"}"
""
"/* ---- session / roles ---- */"
"/* Default to guest, not admin: this is read before loadSession() resolves, and"
"   it is also the correct fallback if that request fails. Defaulting to admin"
"   let the boot-time applyLang() reach refreshActiveTab() with the guard open,"
"   so a visitor's browser fired /status and /scan and logged 401s. */"
"var SESSION={auth_enabled:false,role:'guest',user:'',client_ip:''};"
"/* Bumped whenever the role changes. A load chain that is still in flight when"
"   the user logs out (or back in) would otherwise keep running, 401 on the"
"   remaining requests and could write stale data into the DOM after a re-login. */"
"var loadGen=0;"
"function showLogin(){"
"  document.getElementById('lg-err').textContent='';"
"  document.getElementById('lg-pass').value='';"
"  document.getElementById('lg-user').value=SESSION.user||'admin';"
"  document.getElementById('modal').style.display='flex';"
"  document.getElementById('lg-pass').focus();"
"}"
"function hideLogin(){document.getElementById('modal').style.display='none'}"
"function authButton(){"
"  if(SESSION.role==='admin' && SESSION.auth_enabled){ doLogout() } else { showLogin() }"
"}"
"function loadSession(){"
"  var gen=++loadGen;"
"  return fetch('/api/session').then(function(r){return r.json()}).then(function(d){"
"    if(gen!==loadGen){return}   /* a newer transition already won */"
"    SESSION=d;"
"    var btn=document.getElementById('auth-btn');"
"    if(SESSION.auth_enabled){"
"      btn.textContent=(SESSION.role==='admin')?t('logout_btn'):t('login_btn');"
"    }else{"
"      btn.textContent=t('login_btn');"
"      btn.style.display='none';   /* nothing to log into */"
"    }"
"    var admin=(SESSION.role==='admin');"
"    document.getElementById('admin-view').style.display=admin?'block':'none';"
"    document.getElementById('guest-view').style.display=admin?'none':'block';"
"    if(admin){"
"      /* Show the AP password and the rest of the admin state. */"
"      fetch('/api/appass').then(function(r){return r.json()}).then(function(x){"
"        document.getElementById('current-pass').value=x.password||t('no_pass_set');"
"      }).catch(function(){});"
"      loadSettings(gen);"
"      init();"
"    }else{"
"      var g=document.getElementById('guest-ident');"
"      g.innerHTML=SESSION.client_ip ? (t('guest_you')+': <b>'+SESSION.client_ip+'</b>') : '';"
"      loadGuestView();"
"    }"
"    applyLang();   /* re-label the buttons now that the role is known */"
"  }).catch(function(){"
"    /* Session lookup failed: show the guest view rather than the admin one. */"
"    document.getElementById('admin-view').style.display='none';"
"    document.getElementById('guest-view').style.display='block';"
"  });"
"}"
"function doLogin(){"
"  var u=document.getElementById('lg-user').value.trim();"
"  var p=document.getElementById('lg-pass').value;"
"  var e=document.getElementById('lg-err');"
"  fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'user='+encodeURIComponent(u)+'&pass='+encodeURIComponent(p)})"
"  .then(function(r){"
"    if(r.ok){ hideLogin(); return loadSession() }"
"    e.textContent=t('login_failed');"
"  }).catch(function(){ e.textContent=t('login_failed') });"
"}"
"function doLogout(){"
"  fetch('/logout',{method:'POST'}).then(function(){ loadSession() });"
"}"
"/* A 401 from anywhere means the session went away; drop to the guest view. */"
"function guard(resp){"
"  if(resp && resp.status===401){ loadSession(); return false }"
"  return true;"
"}"
""
"applyLang();initPresets();loadSession();"
"</script></body></html>";

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
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
        if (!caller_may_touch(req, list[i].mac)) {
            continue;
        }
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
    /* Device-scoped: an admin may change any device, a guest only its own and the
     * IoT devices it owns. Refusing here rather than filtering silently, because
     * a write that was quietly ignored would be worse than an error. */
    if (!caller_may_touch(req, mac)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "not your device");
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
    /* Device-scoped: an admin may change any device, a guest only its own and the
     * IoT devices it owns. Refusing here rather than filtering silently, because
     * a write that was quietly ignored would be worse than an error. */
    if (!caller_may_touch(req, mac)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "not your device");
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

static esp_err_t apcfg_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "hidden", s_ap_hidden);
    cJSON_AddNumberToObject(root, "maxconn", s_ap_maxconn);
    cJSON_AddNumberToObject(root, "txpower_dbm", s_txpower_qdbm * 0.25);
    cJSON_AddNumberToObject(root, "txpower_min", AP_TXPOWER_MIN * 0.25);
    cJSON_AddNumberToObject(root, "txpower_max", AP_TXPOWER_MAX * 0.25);
    cJSON_AddNumberToObject(root, "maxconn_max", AP_MAXCONN_MAX);
    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_apcfg_post_handler(httpd_req_t *req)
{
    char buf[192] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_hidden[8] = {0}, raw_conn[8] = {0}, raw_power[16] = {0};
    if (httpd_query_key_value(buf, "hidden", raw_hidden, sizeof(raw_hidden)) != ESP_OK ||
            httpd_query_key_value(buf, "maxconn", raw_conn, sizeof(raw_conn)) != ESP_OK ||
            httpd_query_key_value(buf, "txpower", raw_power, sizeof(raw_power)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "hidden, maxconn and txpower required");
        return ESP_FAIL;
    }

    long conn = strtol(raw_conn, NULL, 10);
    if (conn < AP_MAXCONN_MIN || conn > AP_MAXCONN_MAX) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "max clients out of range");
        return ESP_FAIL;
    }
    /* Percent-decoded so a decimal like 17.25 survives; strtod then rounds to
     * the quarter-dBm step the driver uses. */
    char power_s[16] = {0};
    url_decode(power_s, sizeof(power_s), raw_power);
    double dbm = atof(power_s);
    int q = (int)(dbm * 4.0 + 0.5);
    if (q < AP_TXPOWER_MIN || q > AP_TXPOWER_MAX) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "TX power out of range");
        return ESP_FAIL;
    }

    bool hidden = (raw_hidden[0] == '1' || strcasecmp(raw_hidden, "true") == 0);
    bool need_restart = (hidden != s_ap_hidden) || (conn != s_ap_maxconn);

    s_ap_hidden = hidden;
    s_ap_maxconn = (uint8_t)conn;
    s_txpower_qdbm = (int8_t)q;
    save_ap_settings();

    /* TX power takes effect immediately and does not disturb the link. */
    int8_t eff = 0;
    if (esp_wifi_set_max_tx_power(s_txpower_qdbm) == ESP_OK &&
            esp_wifi_get_max_tx_power(&eff) == ESP_OK) {
        ESP_LOGI(TAG_MAIN, "TX power now %.2f dBm", eff * 0.25f);
    }

    if (need_restart) {
        /* Hide-SSID and the client limit live in the AP config, which only
         * applies on (re)start - and that drops every client, so answer first. */
        httpd_resp_sendstr(req, "OK");
        vTaskDelay(pdMS_TO_TICKS(200));
        apply_ap_config();
        esp_wifi_stop();
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_wifi_start();
        xEventGroupSetBits(s_wifi_eg, STA_BACKOFF_RESET_BIT | STA_NEED_CONNECT_BIT);
        ESP_LOGI(TAG_MAIN, "AP settings applied (hidden=%d maxconn=%u)",
                 s_ap_hidden, s_ap_maxconn);
        return ESP_OK;
    }

    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t acl_get_handler(httpd_req_t *req)
{
    uint8_t macs[AP_ACL_MAX][6];
    int n = ap_acl_list(macs, AP_ACL_MAX);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", ap_acl_enabled());
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        char b[18];
        snprintf(b, sizeof(b), MACSTR, MAC2STR(macs[i]));
        cJSON_AddItemToArray(arr, cJSON_CreateString(b));
    }
    cJSON_AddItemToObject(root, "macs", arr);
    cJSON_AddNumberToObject(root, "max", AP_ACL_MAX);
    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t acl_add_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    char raw[64] = {0}, mac_s[32] = {0};
    if (httpd_query_key_value(buf, "mac", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    url_decode(mac_s, sizeof(mac_s), raw);
    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }
    esp_err_t err = ap_acl_add(mac);
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "list full");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    /* A newly allowed MAC that is somehow already being denied needs no action,
     * but a newly added entry while the list is enabled should be honoured, so
     * nothing to sweep for an add. */
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t acl_del_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    char raw[64] = {0}, mac_s[32] = {0};
    if (httpd_query_key_value(buf, "mac", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    url_decode(mac_s, sizeof(mac_s), raw);
    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }
    if (ap_acl_remove(mac) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not on the list");
        return ESP_FAIL;
    }
    /* Removing an entry while the list is enforced should take effect at once,
     * or the client would stay connected until it roams. */
    ap_acl_enforce_all();
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t acl_enable_post_handler(httpd_req_t *req)
{
    char buf[64] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    char raw[16] = {0};
    if (httpd_query_key_value(buf, "on", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "on required");
        return ESP_FAIL;
    }
    bool on = (raw[0] == '1' || strcasecmp(raw, "true") == 0);
    esp_err_t err = ap_acl_set_enabled(on);
    if (err == ESP_ERR_INVALID_STATE) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "add at least one MAC first: an empty list would kick every client");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    /* Answer first: the sweep below deauthenticates clients, and the caller may
     * well be one of them. */
    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(100));
    ap_acl_enforce_all();
    return ESP_OK;
}

static esp_err_t ssid_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ssid", ap_ssid_full);
    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_ssid_post_handler(httpd_req_t *req)
{
    char buf[192] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw[128] = {0};
    if (httpd_query_key_value(buf, "ssid", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ssid required");
        return ESP_FAIL;
    }
    /* Larger than the 32-char limit so an over-long name reaches the validator
     * instead of being silently truncated into something acceptable. */
    char name[128] = {0};
    url_decode(name, sizeof(name), raw);

    if (!valid_ssid(name)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "1-32 characters, no leading/trailing space, no control characters");
        return ESP_FAIL;
    }
    if (strcmp(name, ap_ssid_full) == 0) {
        httpd_resp_sendstr(req, "OK");   /* unchanged */
        return ESP_OK;
    }

    strncpy(ap_ssid_full, name, sizeof(ap_ssid_full) - 1);
    ap_ssid_full[sizeof(ap_ssid_full) - 1] = '\0';
    save_ap_ssid();

    /* Answer before touching the radio. Changing the SSID restarts WiFi, which
     * tears down this very HTTP connection, so responding first is what keeps a
     * successful change from looking like a failure in the browser. Every client
     * is dropped and the upstream link re-establishes itself. */
    httpd_resp_sendstr(req, "OK");
    vTaskDelay(pdMS_TO_TICKS(200));

    apply_ap_config();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));
    esp_wifi_start();
    xEventGroupSetBits(s_wifi_eg, STA_BACKOFF_RESET_BIT | STA_NEED_CONNECT_BIT);

    ESP_LOGI(TAG_MAIN, "AP name changed to '%s'", ap_ssid_full);
    return ESP_OK;
}

/* Who am I, and is authentication even on? Drives the header and the UI. */
/*
 * Device attributes. An admin sees every record and can edit them; a guest sees
 * only the records it is allowed to (its own device and the IoT devices it owns),
 * which is how it learns about an IoT device that is currently offline and so
 * absent from /api/clients.
 */
static esp_err_t devices_get_handler(httpd_req_t *req)
{
    device_rec_t all[DEVICES_MAX];
    int n = devices_records(all, DEVICES_MAX);
    bool admin = (web_auth_role_of(req) == WEB_ROLE_ADMIN);
    uint8_t me[6] = {0};
    bool have_me = caller_mac(req, me);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "guest_claim", devices_guest_claim_enabled());
    cJSON_AddBoolToObject(root, "clear_on_visit", devices_clear_iot_on_visit());
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        bool mine = have_me && devices_visible(all[i].mac, me);
        if (!admin && (!have_me || !devices_listed_for_guest(all[i].mac, me))) {
            continue;
        }
        cJSON *o = cJSON_CreateObject();
        char b[18];
        snprintf(b, sizeof(b), MACSTR, MAC2STR(all[i].mac));
        cJSON_AddStringToObject(o, "mac", b);
        cJSON_AddBoolToObject(o, "iot", all[i].iot);
        /* For a guest: whether this is one it could claim right now, or one it
         * already holds and may release. */
        /* "Unowned and IoT", i.e. claimable by anyone - not "claimable by the
         * caller". Tying it to the caller made it read false for an admin, which
         * is misleading rather than useful. */
        cJSON_AddBoolToObject(o, "claimable",
                              all[i].iot && !devices_mac_is_set(all[i].owner));
        cJSON_AddBoolToObject(o, "mine", mine);
        if (devices_mac_is_set(all[i].owner)) {
            snprintf(b, sizeof(b), MACSTR, MAC2STR(all[i].owner));
            cJSON_AddStringToObject(o, "owner", b);
        } else {
            cJSON_AddStringToObject(o, "owner", "");
        }
        cJSON_AddItemToArray(arr, o);
    }
    cJSON_AddItemToObject(root, "devices", arr);
    cJSON_AddBoolToObject(root, "admin", admin);
    if (have_me) {
        char b[18];
        snprintf(b, sizeof(b), MACSTR, MAC2STR(me));
        cJSON_AddStringToObject(root, "me", b);
    } else {
        cJSON_AddStringToObject(root, "me", "");
    }

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

/*
 * Claim or release an unowned IoT device. Guest-reachable on purpose: it is how a
 * visitor is given something to manage without logging in.
 *
 * The three refusals matter as much as the success path - only unowned devices
 * can be claimed, so one visitor cannot take a device another already manages;
 * only the current owner may release one; and nothing happens at all unless an
 * administrator has enabled claiming.
 */
static esp_err_t claim_post_handler(httpd_req_t *req)
{
    if (!devices_guest_claim_enabled()) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "claiming is disabled");
        return ESP_FAIL;
    }
    uint8_t me[6] = {0};
    if (!caller_mac(req, me)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                            "your device is not on this network");
        return ESP_FAIL;
    }

    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw[64] = {0}, mac_s[32] = {0};
    if (httpd_query_key_value(buf, "mac", raw, sizeof(raw)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    url_decode(mac_s, sizeof(mac_s), raw);
    uint8_t target[6];
    if (!parse_mac(mac_s, target)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }

    esp_err_t err = devices_claim(target, me);
    if (err == ESP_ERR_INVALID_STATE) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "already owned by someone else");
        return ESP_FAIL;
    }
    if (err == ESP_ERR_INVALID_ARG) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "not an IoT device you can claim");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* Admin only: the two ownership policies. */
static esp_err_t set_devpolicy_post_handler(httpd_req_t *req)
{
    char buf[128] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_claim[8] = {0}, raw_clr[8] = {0};
    if (httpd_query_key_value(buf, "claim", raw_claim, sizeof(raw_claim)) == ESP_OK) {
        devices_set_guest_claim(raw_claim[0] == '1' || strcasecmp(raw_claim, "true") == 0);
    }
    if (httpd_query_key_value(buf, "clearvisit", raw_clr, sizeof(raw_clr)) == ESP_OK) {
        devices_set_clear_iot_on_visit(raw_clr[0] == '1' || strcasecmp(raw_clr, "true") == 0);
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* Admin only: flag a device as IoT and/or set its owner. */
static esp_err_t set_device_post_handler(httpd_req_t *req)
{
    char buf[192] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_mac[64] = {0}, raw_iot[8] = {0}, raw_owner[64] = {0};
    if (httpd_query_key_value(buf, "mac", raw_mac, sizeof(raw_mac)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "mac required");
        return ESP_FAIL;
    }
    httpd_query_key_value(buf, "iot", raw_iot, sizeof(raw_iot));

    /* Read the owner field BEFORE decoding it. A missing field means "leave
     * ownership alone"; an explicitly empty one means "clear it". Splitting the
     * read and the decode is how this went wrong once: the decode ran against a
     * still-empty buffer, so every request looked like "clear". */
    bool owner_given = (httpd_query_key_value(buf, "owner", raw_owner,
                                              sizeof(raw_owner)) == ESP_OK);

    char mac_s[32] = {0}, owner_s[32] = {0};
    url_decode(mac_s, sizeof(mac_s), raw_mac);
    url_decode(owner_s, sizeof(owner_s), raw_owner);

    uint8_t mac[6];
    if (!parse_mac(mac_s, mac)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad MAC");
        return ESP_FAIL;
    }
    bool iot = (raw_iot[0] == '1' || strcasecmp(raw_iot, "true") == 0);

    uint8_t owner[6];
    const uint8_t *owner_p = NULL;
    if (owner_given && owner_s[0] != '\0') {
        if (!parse_mac(owner_s, owner)) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad owner MAC");
            return ESP_FAIL;
        }
        if (memcmp(owner, mac, 6) == 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "a device cannot own itself");
            return ESP_FAIL;
        }
        owner_p = owner;
    }

    esp_err_t err = owner_given ? devices_set(mac, iot, owner_p)
                                : devices_set_iot(mac, iot);
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device table full");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* ======================= firmware update ======================= */

/* Plain text, fixed strings only. httpd_resp_send_err wraps its message in an
 * HTML page, which the upload script would then render into the settings panel;
 * a short text body reads better there and cannot carry anything injected. */
static esp_err_t ota_fail(httpd_req_t *req, const char *status, const char *msg)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
    return ESP_FAIL;
}

/*
 * Discard the rest of the request body before answering.
 *
 * Answering while body bytes are still unread desynchronises the connection:
 * the status line reaches the client but the body does not, so a rejected
 * upload shows up as a bare 500 with no explanation. This was a real bug - an
 * upload caught on its first chunk (esp_ota_write validates the image magic
 * byte immediately) left most of the body unread and the reason never arrived.
 */
static void ota_drain(httpd_req_t *req, int remaining)
{
    char sink[256];
    while (remaining > 0) {
        int want = (remaining < (int)sizeof(sink)) ? remaining : (int)sizeof(sink);
        int got = httpd_req_recv(req, sink, want);
        if (got == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (got <= 0) {
            return;   /* client went away; nothing left to drain */
        }
        remaining -= got;
    }
}

/*
 * Accepts the app image as a raw request body (not multipart), so there is no
 * form parsing: the browser sends the File object itself and we stream it
 * straight into the inactive slot.
 *
 * The slot selection, the validation and the boot-partition switch all live in
 * fw_update.c, shared with the automatic updater. That sequence decides what
 * the device boots next; a second copy of it here would eventually disagree
 * with the first, and the consequence of that disagreement is a device that
 * does not come back.
 *
 * The boot partition is switched only after the image is fully written and
 * accepted, so a truncated upload, a corrupt image or a failed write leaves the
 * running firmware untouched.
 */
static esp_err_t ota_post_handler(httpd_req_t *req)
{
    if (req->content_len <= 0) {
        return ota_fail(req, "400 Bad Request", "empty body");
    }

    const esp_partition_t *part = NULL;
    esp_ota_handle_t handle = 0;
    esp_err_t err = fw_ota_begin((size_t)req->content_len, &part, &handle);
    if (err != ESP_OK) {
        ota_drain(req, req->content_len);
        switch (err) {
        case ESP_ERR_INVALID_SIZE:
            return ota_fail(req, "400 Bad Request", "image is larger than the OTA slot");
        case ESP_ERR_NOT_FOUND:
            return ota_fail(req, "500 Internal Server Error", "no OTA partition");
        default:
            return ota_fail(req, "500 Internal Server Error", "cannot start the update");
        }
    }

    ESP_LOGW(TAG_MAIN, "OTA: writing %d bytes to %s",
             (int)req->content_len, part->label);

    /* Internal RAM on purpose. esp_ota_write runs with the flash cache off, and
     * on this chip PSRAM is only reachable through that cache. */
    char *buf = heap_caps_malloc(FW_OTA_CHUNK, MALLOC_CAP_INTERNAL);
    if (buf == NULL) {
        fw_ota_abort(handle);
        ota_drain(req, req->content_len);
        return ota_fail(req, "500 Internal Server Error", "out of memory");
    }

    int remaining = req->content_len;
    int total = 0;
    const char *why = NULL;
    esp_err_t write_err = ESP_OK;

    while (remaining > 0) {
        int want = (remaining < FW_OTA_CHUNK) ? remaining : FW_OTA_CHUNK;
        int got = httpd_req_recv(req, buf, want);
        if (got == HTTPD_SOCK_ERR_TIMEOUT) {
            /* A WiFi hiccup, not a reason to throw the upload away. */
            continue;
        }
        if (got <= 0) {
            why = "connection lost during upload";
            break;
        }
        err = esp_ota_write(handle, buf, got);
        if (err != ESP_OK) {
            /* esp_ota_write validates the image as it goes: a body that is not
             * an app image at all is refused on the first chunk, with the magic
             * byte named in the log. */
            ESP_LOGE(TAG_MAIN, "esp_ota_write: %s", esp_err_to_name(err));
            write_err = err;
            why = "flash write failed";
            break;
        }
        remaining -= got;
        total += got;
    }
    free(buf);

    if (why != NULL) {
        fw_ota_abort(handle);
        /* remaining > 0 here: the loop stopped part way through the body. */
        ota_drain(req, remaining);
        ESP_LOGE(TAG_MAIN, "OTA aborted after %d bytes: %s (%s)",
                 total, why, esp_err_to_name(write_err));
        if (fw_ota_err_is_bad_image(write_err)) {
            return ota_fail(req, "400 Bad Request", "not a valid firmware image");
        }
        return ota_fail(req, "500 Internal Server Error", why);
    }

    char newver[32] = {0};
    fw_ota_result_t res = fw_ota_finish(handle, part, newver, sizeof(newver));
    if (res != FW_OTA_OK) {
        /* A well-formed image that is simply not ours is the caller's mistake,
         * so it answers 400; anything else is ours to own. */
        bool client_fault = (res == FW_OTA_BAD_IMAGE ||
                             res == FW_OTA_NO_DESCRIPTOR ||
                             res == FW_OTA_WRONG_PROJECT);
        return ota_fail(req, client_fault ? "400 Bad Request"
                                          : "500 Internal Server Error",
                        fw_ota_result_text(res));
    }

    ESP_LOGW(TAG_MAIN, "OTA: %d bytes into %s, version %s; restarting in 2s",
             total, part->label, newver);
    httpd_resp_sendstr(req, "OK");

    /* Reboot only once the response is on the wire. Restarting first makes the
     * browser report a network error, and the user cannot tell success from
     * failure. */
    fw_schedule_reboot();
    return ESP_OK;
}

/* Which build is installed, and which slot it is running from. The slot label
 * is the point: it is how you confirm an update actually switched slots. */
static esp_err_t version_get_handler(httpd_req_t *req)
{
    const esp_app_desc_t *d = esp_app_get_description();
    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "version", d ? d->version : "");
    cJSON_AddStringToObject(root, "project", d ? d->project_name : "");
    cJSON_AddStringToObject(root, "date",    d ? d->date : "");
    cJSON_AddStringToObject(root, "time",    d ? d->time : "");
    cJSON_AddStringToObject(root, "idf",     d ? d->idf_ver : "");
    cJSON_AddStringToObject(root, "slot",    run ? run->label : "");
    cJSON_AddStringToObject(root, "next",    next ? next->label : "");

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

/* ==================== automatic firmware update ==================== */

static const char *fw_state_name(fw_state_t st)
{
    switch (st) {
    case FW_IDLE:        return "idle";
    case FW_CHECKING:    return "checking";
    case FW_UP_TO_DATE:  return "uptodate";
    case FW_AVAILABLE:   return "available";
    case FW_DOWNLOADING: return "downloading";
    case FW_INSTALLING:  return "installing";
    case FW_ERROR:       return "error";
    }
    return "unknown";
}

/*
 * Everything the firmware panel needs, in one request.
 *
 * /api/version stays as the small probe (it answers "what am I running" and
 * little else); this is the one the panel polls, including while a download is
 * in flight, so it has to be cheap and self-contained.
 */
static esp_err_t update_get_handler(httpd_req_t *req)
{
    fw_status_t s;
    fw_update_status(&s);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "state", fw_state_name(s.state));
    cJSON_AddStringToObject(root, "running", s.running);
    cJSON_AddStringToObject(root, "latest", s.latest);
    cJSON_AddStringToObject(root, "slot", s.slot);
    cJSON_AddStringToObject(root, "url", s.url);
    cJSON_AddStringToObject(root, "error", s.error);
    cJSON_AddNumberToObject(root, "interval_hours", s.interval_hours);
    cJSON_AddBoolToObject(root, "auto_install", s.auto_install);
    /* A development build has no update path, so the panel disables the whole
     * section rather than offering controls that cannot work. */
    cJSON_AddBoolToObject(root, "release_build", s.release_build);
    cJSON_AddStringToObject(root, "build_repo", s.build_repo);
    cJSON_AddNumberToObject(root, "progress", s.progress);
    /* Seconds since boot, so the UI can render "checked N minutes ago" without
     * the device needing a wall clock. 0 means never checked. */
    cJSON_AddNumberToObject(root, "last_check_ago",
                            s.last_check_us > 0
                                ? (double)((esp_timer_get_time() - s.last_check_us) / 1000000)
                                : 0);

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t ota_check_post_handler(httpd_req_t *req)
{
    fw_update_check_now();
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t ota_install_post_handler(httpd_req_t *req)
{
    fw_update_install_now();
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t set_otacfg_post_handler(httpd_req_t *req)
{
    char buf[512] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_hours[16] = {0}, raw_auto[8] = {0}, raw_url[288] = {0};
    if (httpd_query_key_value(buf, "hours", raw_hours, sizeof(raw_hours)) == ESP_OK) {
        long h = strtol(raw_hours, NULL, 10);
        if (h < 0) {
            h = 0;
        }
        if (fw_update_set_interval((uint32_t)h) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad interval");
            return ESP_FAIL;
        }
    }
    if (httpd_query_key_value(buf, "auto", raw_auto, sizeof(raw_auto)) == ESP_OK) {
        bool want = (raw_auto[0] == '1' || strcasecmp(raw_auto, "true") == 0);
        /* A refusal has to be reported. Answering 200 to an operation that did
         * nothing leaves a switch that springs back with no explanation, which
         * is the failure mode the guard exists to avoid. */
        if (fw_update_set_auto(want) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "this firmware was built from a modified source tree");
            return ESP_FAIL;
        }
    }
    if (httpd_query_key_value(buf, "url", raw_url, sizeof(raw_url)) == ESP_OK) {
        char url_s[288] = {0};
        url_decode(url_s, sizeof(url_s), raw_url);
        if (url_s[0] != '\0' && fw_update_set_url(url_s) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "url must be http:// and under 256 characters");
            return ESP_FAIL;
        }
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* ==================== developer mode (token flashing) ==================== */

/*
 * The token is returned here in full. It has to be, so the panel can show it to
 * the administrator to put in a script; there is no way to script a flash
 * without knowing it. This endpoint is admin-only and is NOT itself
 * token-authorized, so holding the token does not let you read it back - which
 * also means a token cannot be used to extend its own life.
 */
static esp_err_t devmode_get_handler(httpd_req_t *req)
{
    char token[FW_DEV_TOKEN_LEN];
    fw_dev_token(token, sizeof(token));

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "enabled", fw_dev_mode());
    cJSON_AddStringToObject(root, "token", token);
    cJSON_AddStringToObject(root, "header", "X-OTA-Token");

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_devmode_post_handler(httpd_req_t *req)
{
    char buf[96] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_on[8] = {0}, raw_regen[8] = {0};
    if (httpd_query_key_value(buf, "on", raw_on, sizeof(raw_on)) == ESP_OK) {
        fw_set_dev_mode(raw_on[0] == '1' || strcasecmp(raw_on, "true") == 0);
    }
    if (httpd_query_key_value(buf, "regen", raw_regen, sizeof(raw_regen)) == ESP_OK &&
            (raw_regen[0] == '1' || strcasecmp(raw_regen, "true") == 0)) {
        /* Only meaningful while the mode is on; rotating a token nobody can use
         * would just be a confusing way to say "nothing happened". */
        if (!fw_dev_mode()) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "enable developer mode before rotating the token");
            return ESP_FAIL;
        }
        fw_dev_token_regen();
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t session_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    web_role_t role = web_auth_role_of(req);
    cJSON_AddBoolToObject(root, "auth_enabled", web_auth_enabled());
    cJSON_AddStringToObject(root, "role", role == WEB_ROLE_ADMIN ? "admin" : "guest");
    cJSON_AddStringToObject(root, "user", web_auth_user());
    cJSON_AddNumberToObject(root, "session_seconds", web_auth_session_seconds());

    /* A guest's own device, so the UI can say which one it is showing. */
    uint32_t ip = 0;
    if (web_auth_client_ip(req, &ip)) {
        esp_ip4_addr_t a = { .addr = ip };
        char b[16];
        snprintf(b, sizeof(b), IPSTR, IP2STR(&a));
        cJSON_AddStringToObject(root, "client_ip", b);
    }

    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_user[64] = {0}, raw_pass[128] = {0};
    httpd_query_key_value(buf, "user", raw_user, sizeof(raw_user));
    if (httpd_query_key_value(buf, "pass", raw_pass, sizeof(raw_pass)) != ESP_OK) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":\"password required\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    char user[64] = {0}, pass[128] = {0};
    url_decode(user, sizeof(user), raw_user);
    url_decode(pass, sizeof(pass), raw_pass);
    if (user[0] == '\0') {
        snprintf(user, sizeof(user), "%s", web_auth_user());
    }

    char token[WEB_TOKEN_LEN + 1];
    esp_err_t err = web_auth_login(user, pass, token, sizeof(token));
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":\"invalid credentials\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    /* The buffer must outlive the send: httpd_resp_set_hdr() stores the pointer
     * rather than copying it, so a helper-local buffer would be read back from
     * reused stack. */
    char cookie[160];
    web_auth_cookie_for(token, cookie, sizeof(cookie));
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t logout_post_handler(httpd_req_t *req)
{
    web_auth_logout(req);
    httpd_resp_set_hdr(req, "Set-Cookie", WEB_AUTH_COOKIE_CLEAR);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* Admin-only view of the credential state. */
static esp_err_t webauth_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "user", web_auth_user());
    /* Never the password itself - only whether one is set. */
    cJSON_AddBoolToObject(root, "enabled", web_auth_enabled());
    const char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, strlen(json));
    free((void *)json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t set_webauth_post_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    size_t want = (req->content_len < sizeof(buf) - 1) ? req->content_len : sizeof(buf) - 1;
    int ret = httpd_req_recv(req, buf, want);
    if (ret <= 0) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char raw_user[64] = {0}, raw_pass[128] = {0};
    httpd_query_key_value(buf, "user", raw_user, sizeof(raw_user));
    if (httpd_query_key_value(buf, "pass", raw_pass, sizeof(raw_pass)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "pass required (empty to disable)");
        return ESP_FAIL;
    }
    char user[64] = {0}, pass[128] = {0};
    url_decode(user, sizeof(user), raw_user);
    url_decode(pass, sizeof(pass), raw_pass);

    esp_err_t err = web_auth_set_credentials(user, pass);
    if (err == ESP_ERR_INVALID_ARG) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "password must be 8-64 characters; user 1-32 with no ':'");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* Every session was dropped, including this one if a password is now set, so
     * tell the UI to re-establish itself. */
    if (web_auth_enabled()) {
        httpd_resp_set_status(req, "200 OK");
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
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
        if (!caller_may_touch(req, list[i].mac)) {
            continue;
        }
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
    /* Device-scoped: an admin may change any device, a guest only its own and the
     * IoT devices it owns. Refusing here rather than filtering silently, because
     * a write that was quietly ignored would be worse than an error. */
    if (!caller_may_touch(req, mac)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "not your device");
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
    /* Device-scoped: an admin may change any device, a guest only its own and the
     * IoT devices it owns. Refusing here rather than filtering silently, because
     * a write that was quietly ignored would be worse than an error. */
    if (!caller_may_touch(req, mac)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "not your device");
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

    /* Probe "example.com" by default, or a name of the caller's choosing.
     * Being able to ask the device what it resolves is the difference between
     * diagnosing a resolution problem and guessing at one - and the relay's own
     * cache and circuit breakers are only visible through it. */
    char name[128] = "example.com";
    char q[192];
    if (httpd_req_get_url_query_len(req) > 0 &&
            httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char raw[128] = {0};
        if (httpd_query_key_value(q, "name", raw, sizeof(raw)) == ESP_OK) {
            url_decode(name, sizeof(name), raw);
        }
    }

    doh_relay_probe(DNS_MODE_DOH, def, name, result, sizeof(result));
    cJSON *d = cJSON_CreateObject();
    cJSON_AddStringToObject(d, "addr", def);
    cJSON_AddStringToObject(d, "mode", "doh");
    cJSON_AddStringToObject(d, "name", name);
    cJSON_AddStringToObject(d, "result", result);
    cJSON_AddItemToObject(root, "default", d);

    dns_rule_t list[DNS_RULE_MAX];
    int n = dns_rules_list(list, DNS_RULE_MAX);
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), MACSTR, MAC2STR(list[i].mac));
        doh_relay_probe(list[i].mode, list[i].addr, name, result, sizeof(result));
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
        /* A guest sees its own device, the IoT devices it owns, and unowned IoT
         * devices it is allowed to claim - it has to see one before it can claim
         * it. An admin sees everything. Filtering here rather than refusing the
         * request keeps one endpoint serving both roles. */
        if (web_auth_role_of(req) != WEB_ROLE_ADMIN) {
            uint8_t me[6] = {0};
            if (!caller_mac(req, me) || !devices_listed_for_guest(list[i].mac, me)) {
                continue;
            }
        }
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
    cfg.max_uri_handlers = 60;
    cfg.stack_size = 6144;
    /*
     * Purge the least-recently-used session when the socket pool is full.
     *
     * This must stay ON. Turning it off seemed better - an overflow would fail
     * visibly instead of silently resetting the losers - but that reasoning
     * missed keep-alive: browsers hold connections open, and with no eviction an
     * idle handful of them exhausts the pool permanently and the panel becomes
     * completely unreachable (ping still works, HTTP answers nothing) until the
     * clients disconnect. That is far worse than one panel rendering empty.
     *
     * Page loads also serialise their requests, so the pool should never fill in
     * normal use; purging is the safety net for when it does.
     */
    cfg.lru_purge_enable = true;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG_MAIN, "could not start the web server");
        return;
    }

    /* Static, because httpd_register_uri_handler stores the user_ctx pointer and
     * it has to outlive this call. */
    static route_t routes[] = {
        { { .uri = "/",                 .method = HTTP_GET }, root_get_handler, false, false },
        { { .uri = "/status",           .method = HTTP_GET }, status_get_handler, true, false },
        { { .uri = "/scan",             .method = HTTP_GET }, scan_get_handler, true, false },
        { { .uri = "/connect",          .method = HTTP_POST }, connect_post_handler, true, false },
        { { .uri = "/api/appass",       .method = HTTP_GET }, ap_pass_get_handler, true, false },
        { { .uri = "/setpass",          .method = HTTP_POST }, set_pass_post_handler, true, false },
        { { .uri = "/resetpass",        .method = HTTP_POST }, reset_pass_handler, true, false },
        { { .uri = "/api/dohurl",       .method = HTTP_GET }, doh_url_get_handler, true, false },
        { { .uri = "/setdohurl",        .method = HTTP_POST }, set_doh_url_post_handler, true, false },
        { { .uri = "/api/clients",      .method = HTTP_GET }, clients_get_handler, false, false },
        { { .uri = "/api/radio",        .method = HTTP_GET }, radio_get_handler, true, false },
        { { .uri = "/setradio",         .method = HTTP_POST }, set_radio_post_handler, true, false },
        { { .uri = "/api/leases",       .method = HTTP_GET }, leases_get_handler, false, false },
        { { .uri = "/lease/add",        .method = HTTP_POST }, add_lease_post_handler, false, false },
        { { .uri = "/lease/del",        .method = HTTP_POST }, del_lease_post_handler, false, false },
        { { .uri = "/api/dnsrules",     .method = HTTP_GET }, dnsrules_get_handler, false, false },
        { { .uri = "/api/hostname",     .method = HTTP_GET }, hostname_get_handler, true, false },
        { { .uri = "/sethostname",      .method = HTTP_POST }, set_hostname_post_handler, true, false },
        { { .uri = "/dnsrule/set",      .method = HTTP_POST }, set_dnsrule_post_handler, false, false },
        { { .uri = "/dnsrule/del",      .method = HTTP_POST }, del_dnsrule_post_handler, false, false },
        { { .uri = "/api/dnstest",      .method = HTTP_GET }, dnstest_get_handler, true, false },
        { { .uri = "/api/portmaps",     .method = HTTP_GET }, portmaps_get_handler, true, false },
        { { .uri = "/portmap/add",      .method = HTTP_POST }, add_portmap_post_handler, true, false },
        { { .uri = "/portmap/del",      .method = HTTP_POST }, del_portmap_post_handler, true, false },
        { { .uri = "/api/ssid",         .method = HTTP_GET }, ssid_get_handler, true, false },
        { { .uri = "/api/apcfg",        .method = HTTP_GET }, apcfg_get_handler, true, false },
        { { .uri = "/setapcfg",         .method = HTTP_POST }, set_apcfg_post_handler, true, false },
        { { .uri = "/api/acl",          .method = HTTP_GET }, acl_get_handler, true, false },
        { { .uri = "/acl/add",          .method = HTTP_POST }, acl_add_post_handler, true, false },
        { { .uri = "/acl/del",          .method = HTTP_POST }, acl_del_post_handler, true, false },
        { { .uri = "/acl/enable",       .method = HTTP_POST }, acl_enable_post_handler, true, false },
        { { .uri = "/setssid",          .method = HTTP_POST }, set_ssid_post_handler, true, false },
        { { .uri = "/api/devices",  .method = HTTP_GET  }, devices_get_handler, false, false },
        { { .uri = "/device/set",   .method = HTTP_POST }, set_device_post_handler, true, false },
        { { .uri = "/claim",        .method = HTTP_POST }, claim_post_handler, false, false },
        { { .uri = "/setdevpolicy", .method = HTTP_POST }, set_devpolicy_post_handler, true, false },

        /* Firmware update. Admin-only: this rewrites the boot partition, and
         * the automatic updater pulls executable code off the network.
         *
         * The three OTA routes also accept the developer token, so a script can
         * flash without a panel session. Nothing else does - see route_t. */
        { { .uri = "/api/version",  .method = HTTP_GET  }, version_get_handler, true, false },
        { { .uri = "/ota",          .method = HTTP_POST }, ota_post_handler,      true, true  },
        { { .uri = "/api/update",   .method = HTTP_GET  }, update_get_handler,    true, false },
        { { .uri = "/ota/check",    .method = HTTP_POST }, ota_check_post_handler,true, true  },
        { { .uri = "/ota/install",  .method = HTTP_POST }, ota_install_post_handler,true, true },
        { { .uri = "/setotacfg",    .method = HTTP_POST }, set_otacfg_post_handler,true, false },
        { { .uri = "/api/devmode",  .method = HTTP_GET  }, devmode_get_handler,   true, false },
        { { .uri = "/setdevmode",   .method = HTTP_POST }, set_devmode_post_handler,true,false },

        { { .uri = "/api/session",      .method = HTTP_GET }, session_get_handler, false, false },
        { { .uri = "/login",            .method = HTTP_POST }, login_post_handler, false, false },
        { { .uri = "/logout",           .method = HTTP_POST }, logout_post_handler, false, false },
        { { .uri = "/api/webauth",      .method = HTTP_GET }, webauth_get_handler, true, false },
        { { .uri = "/setwebauth",       .method = HTTP_POST }, set_webauth_post_handler, true, false },
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        routes[i].uri.handler = auth_trampoline;
        routes[i].uri.user_ctx = &routes[i];
        if (httpd_register_uri_handler(server, &routes[i].uri) != ESP_OK) {
            ESP_LOGE(TAG_MAIN, "could not register %s", routes[i].uri.uri);
        }
    }
    ESP_LOGI(TAG_MAIN, "web interface ready on http://%s.local/ (AP: http://192.168.4.1/)",
             s_mdns_host);
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
    load_ap_ssid();
    web_auth_init();
    load_ap_settings();
    ap_acl_init();
    devices_init();
    load_radio_settings();

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

    /* Default 80 * 0.25 dBm = 20 dBm, the 2.4 GHz ceiling for CN; the world-safe
     * default can be lower. Only settable once the driver has started. */
    esp_err_t perr = esp_wifi_set_max_tx_power(s_txpower_qdbm);
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
    ESP_LOGI(TAG_MAIN, "AP: hidden=%d maxconn=%u txpower=%.2f dBm",
             s_ap_hidden, s_ap_maxconn, s_txpower_qdbm * 0.25f);
    /* Kick anyone already associated who is not allowed, in case the list was
     * enabled while the AP was down. */
    ap_acl_enforce_all();

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

    /* After the network is on its way: the task it creates immediately blocks
     * until the station has an address. */
    fw_update_init();

    /* Reaching here means the image boots far enough to bring up WiFi, the DNS
     * relay and the panel, so it counts as good and a boot-time rollback is
     * cancelled. Doing it this early keeps the window in which a reset would be
     * mistaken for a failed boot down to a couple of seconds. It returns an
     * error when the running image is not pending verification (a wired flash,
     * or an already-confirmed OTA), which is not a problem. */
    esp_err_t roll = esp_ota_mark_app_valid_cancel_rollback();
    if (roll == ESP_OK) {
        ESP_LOGW(TAG_MAIN, "OTA image confirmed; rollback cancelled");
    }
}
