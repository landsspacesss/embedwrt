/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_app_desc.h"
#include "esp_timer.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "psa/crypto.h"

#include "fw_update.h"

#define TAG "fw_update"

/*
 * What this firmware was built from, supplied by CMakeLists.txt. Empty when
 * there was no git to ask (a source tarball), which makes the build
 * unattributed - see the guard in do_check().
 */
#ifndef FW_BUILD_REPO
#define FW_BUILD_REPO ""
#endif
#ifndef FW_BUILD_DIRTY
#define FW_BUILD_DIRTY 0
#endif

#define NVS_NAMESPACE "storage"
#define NVS_KEY_INTERVAL "otachk"    /* u32 hours; 0 = periodic checks off */
#define NVS_KEY_AUTO     "otaauto"   /* u8: install without asking */
#define NVS_KEY_URL      "ota_url"   /* str: release feed endpoint */
#define NVS_KEY_DEVMODE  "devmode"   /* u8: token-authorized flashing */
#define NVS_KEY_DEVTOK   "devtoken"  /* str: 64 hex chars */

/* Own key, not a field in a record blob: growing a blob fails its size check
 * on load and silently wipes it. */
static bool s_dev_mode;
static char s_dev_token[FW_DEV_TOKEN_LEN];

/*
 * Where to ask by default. A "latest release" endpoint rather than a file, so
 * publishing a release is all it takes to make a new version visible - no
 * firmware change and no URL to edit.
 *
 * GitHub rather than a LAN server for two reasons: it is not a machine in this
 * house that can be switched off, and the repository is public so no token is
 * involved (the endpoint is readable anonymously). Unauthenticated GitHub API
 * access allows 60 requests an hour per address; one check a day is far below
 * that.
 *
 * Overridable from the panel, so a fork, another network or a self-hosted
 * mirror all work without rebuilding.
 */
#define DEFAULT_URL \
    "https://api.github.com/repos/landsspacesss/embedwrt/releases/latest"

/*
 * Cap on the release metadata. Gitea returns the whole release including its
 * notes, and the fields we need are not all at the front: ``assets`` comes
 * before ``body`` but ``tag_name`` comes after it. Truncating would therefore
 * drop the version and make an available update look like "already up to date",
 * which is why exceeding this is an error rather than a silent trim.
 */
#define FW_JSON_MAX (32 * 1024)

#define FW_HTTP_TIMEOUT_MS 20000

#define UPD_ONLINE_BIT  BIT0
#define UPD_CHECK_BIT   BIT1
#define UPD_INSTALL_BIT BIT2

static SemaphoreHandle_t s_lock;
static EventGroupHandle_t s_eg;

/* Settings, persisted. Single source of truth; the snapshot below is built from
 * these plus the runtime state. */
static uint32_t s_interval_hours = 24;
static bool     s_auto_install;
static char     s_url[256] = DEFAULT_URL;

/* Runtime state, all guarded by s_lock. */
static fw_state_t s_state = FW_IDLE;
static char       s_latest[32];
static char       s_error[FW_ERR_MAX];
static int        s_progress;
static int64_t    s_last_check_us;

/* What the last check found: a newer release and everything needed to fetch and
 * verify it. Kept apart from the snapshot because the panel has no use for it. */
static char   s_dl_url[256];
static char   s_sha_url[256];
static size_t s_img_size;

/* ======================= OTA primitives ======================= */

const char *fw_ota_result_text(fw_ota_result_t r)
{
    switch (r) {
    case FW_OTA_OK:             return "ok";
    case FW_OTA_NO_SLOT:        return "no OTA slot";
    case FW_OTA_TOO_BIG:        return "image is larger than the OTA slot";
    case FW_OTA_BEGIN_FAILED:   return "cannot start the update";
    case FW_OTA_WRITE_FAILED:   return "flash write failed";
    case FW_OTA_BAD_IMAGE:      return "not a valid firmware image";
    case FW_OTA_NO_DESCRIPTOR:  return "image carries no app descriptor";
    case FW_OTA_WRONG_PROJECT:  return "image is for a different project";
    case FW_OTA_SWITCH_FAILED:  return "cannot switch boot partition";
    }
    return "unknown";
}

bool fw_ota_err_is_bad_image(esp_err_t err)
{
    return err == ESP_ERR_OTA_VALIDATE_FAILED || err == ESP_ERR_INVALID_ARG;
}

esp_err_t fw_ota_begin(size_t len, const esp_partition_t **part,
                       esp_ota_handle_t *handle)
{
    const esp_partition_t *p = esp_ota_get_next_update_partition(NULL);
    if (p == NULL) {
        ESP_LOGE(TAG, "no OTA slot to write to");
        return ESP_ERR_NOT_FOUND;
    }
    if (len > p->size) {
        ESP_LOGE(TAG, "%u bytes does not fit %s (%u bytes)",
                 (unsigned)len, p->label, (unsigned)p->size);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = esp_ota_begin(p, len, handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(err));
        return err;
    }
    *part = p;
    return ESP_OK;
}

fw_ota_result_t fw_ota_finish(esp_ota_handle_t handle, const esp_partition_t *part,
                              char *version_out, size_t version_len)
{
    esp_err_t err = esp_ota_end(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(err));
        return FW_OTA_BAD_IMAGE;
    }

    esp_app_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    if (esp_ota_get_partition_description(part, &desc) != ESP_OK) {
        return FW_OTA_NO_DESCRIPTOR;
    }
    if (strcmp(desc.project_name, "embedwrt") != 0) {
        /* Logged, never echoed into a response: the name is whatever was
         * uploaded, and this path is reachable from an unauthenticated-ish
         * surface in the sense that the file content is attacker-chosen. */
        ESP_LOGE(TAG, "rejected: image is for project '%s', not 'embedwrt'",
                 desc.project_name);
        return FW_OTA_WRONG_PROJECT;
    }

    if ((err = esp_ota_set_boot_partition(part)) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition: %s", esp_err_to_name(err));
        return FW_OTA_SWITCH_FAILED;
    }

    if (version_out != NULL && version_len > 0) {
        snprintf(version_out, version_len, "%s", desc.version);
    }
    ESP_LOGW(TAG, "image %s accepted into %s", desc.version, part->label);
    return FW_OTA_OK;
}

void fw_ota_abort(esp_ota_handle_t handle)
{
    esp_ota_abort(handle);
}

static void reboot_cb(void *arg)
{
    esp_restart();
}

void fw_schedule_reboot(void)
{
    esp_timer_create_args_t args = {0};
    args.callback = reboot_cb;
    args.name = "ota_reboot";
    esp_timer_handle_t timer = NULL;
    if (esp_timer_create(&args, &timer) == ESP_OK) {
        esp_timer_start_once(timer, 2 * 1000 * 1000);
    } else {
        esp_restart();
    }
}

/* ======================= settings ======================= */

static void load_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }

    uint32_t u32 = 0;
    if (nvs_get_u32(h, NVS_KEY_INTERVAL, &u32) == ESP_OK) {
        s_interval_hours = u32;
    }
    uint8_t u8 = 0;
    if (nvs_get_u8(h, NVS_KEY_AUTO, &u8) == ESP_OK) {
        s_auto_install = (u8 != 0);
    }
    size_t len = sizeof(s_url);
    if (nvs_get_str(h, NVS_KEY_URL, s_url, &len) != ESP_OK || s_url[0] == '\0') {
        snprintf(s_url, sizeof(s_url), "%s", DEFAULT_URL);
    }
    if (nvs_get_u8(h, NVS_KEY_DEVMODE, &u8) == ESP_OK) {
        s_dev_mode = (u8 != 0);
    }
    len = sizeof(s_dev_token);
    if (nvs_get_str(h, NVS_KEY_DEVTOK, s_dev_token, &len) != ESP_OK) {
        s_dev_token[0] = '\0';
    }
    nvs_close(h);

    /*
     * A build with uncommitted changes does not auto-install, whatever the
     * stored setting says. The stored value is left alone rather than
     * overwritten, so rebuilding from a clean tree restores the user's choice
     * instead of silently forgetting it.
     */
    if (FW_BUILD_DIRTY && s_auto_install) {
        s_auto_install = false;
        ESP_LOGW(TAG, "this build has local modifications, so auto-install is off");
    }

    ESP_LOGI(TAG, "check every %u h, auto-install %s, developer mode %s",
             (unsigned)s_interval_hours, s_auto_install ? "on" : "off",
             s_dev_mode ? "ENABLED" : "off");
}

esp_err_t fw_update_set_interval(uint32_t hours)
{
    if (hours > 24 * 30) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_interval_hours = hours;
    xSemaphoreGive(s_lock);

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_u32(h, NVS_KEY_INTERVAL, hours);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "check interval now %u h (0 = off)", (unsigned)hours);
    /* Wake the task so a newly enabled interval takes effect now rather than
     * after the old one expires. */
    xEventGroupSetBits(s_eg, UPD_CHECK_BIT);
    return ESP_OK;
}

esp_err_t fw_update_set_auto(bool on)
{
    /* Refused rather than quietly ignored: a switch that springs back with no
     * explanation is worse than one that says why. The panel reports this. */
    if (on && FW_BUILD_DIRTY) {
        ESP_LOGW(TAG, "cannot enable auto-install: this build has local modifications");
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_auto_install = on;
    xSemaphoreGive(s_lock);

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_u8(h, NVS_KEY_AUTO, on ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "installing new versions automatically is now %s",
             on ? "ENABLED" : "off");
    return ESP_OK;
}

esp_err_t fw_update_set_url(const char *url)
{
    if (url == NULL || url[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    /*
     * http or https. https is what a public feed needs (GitHub has no plain
     * HTTP endpoint), and it costs about two seconds of handshake per
     * connection on this chip - acceptable for a once-a-day check, and the
     * reason a LAN mirror is still worth allowing.
     *
     * Anything else is refused so that a typo surfaces here rather than as an
     * unsupported-protocol error at check time.
     */
    if (strncmp(url, "https://", 8) != 0 && strncmp(url, "http://", 7) != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(url) >= sizeof(s_url)) {
        return ESP_ERR_INVALID_SIZE;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    snprintf(s_url, sizeof(s_url), "%s", url);
    xSemaphoreGive(s_lock);

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_str(h, NVS_KEY_URL, s_url);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

void fw_update_set_online(bool online)
{
    if (s_eg == NULL) {
        return;
    }
    if (online) {
        xEventGroupSetBits(s_eg, UPD_ONLINE_BIT);
    } else {
        xEventGroupClearBits(s_eg, UPD_ONLINE_BIT);
    }
}

/* ======================= developer mode ======================= */

/* 32 random bytes as lowercase hex. */
static void gen_token(char *out)
{
    uint8_t raw[32];
    static const char hex[] = "0123456789abcdef";

    esp_fill_random(raw, sizeof(raw));
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2]     = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0x0f];
    }
    out[64] = '\0';
}

static esp_err_t save_dev_settings(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_u8(h, NVS_KEY_DEVMODE, s_dev_mode ? 1 : 0);
    nvs_set_str(h, NVS_KEY_DEVTOK, s_dev_token);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

bool fw_dev_mode(void)
{
    return s_dev_mode;
}

void fw_dev_token(char *out, size_t out_len)
{
    if (out == NULL || out_len == 0) {
        return;
    }
    /*
     * The web server starts before this module is initialised, so a request can
     * arrive with no mutex yet. Nothing can be writing then either, so reading
     * without it is correct rather than merely convenient.
     */
    if (s_lock == NULL) {
        snprintf(out, out_len, "%s", s_dev_token);
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    snprintf(out, out_len, "%s", s_dev_token);
    xSemaphoreGive(s_lock);
}

esp_err_t fw_dev_token_regen(void)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    char fresh[FW_DEV_TOKEN_LEN];
    gen_token(fresh);

    xSemaphoreTake(s_lock, portMAX_DELAY);
    snprintf(s_dev_token, sizeof(s_dev_token), "%s", fresh);
    xSemaphoreGive(s_lock);

    ESP_LOGW(TAG, "developer token replaced");
    return save_dev_settings();
}

esp_err_t fw_set_dev_mode(bool on)
{
    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_dev_mode = on;
    /* A mode with no token would be unusable, so mint one the first time it is
     * switched on rather than making the panel do it in a second step. */
    bool need_token = (on && s_dev_token[0] == '\0');
    if (need_token) {
        gen_token(s_dev_token);
    }
    xSemaphoreGive(s_lock);

    if (need_token) {
        ESP_LOGW(TAG, "developer mode enabled; a token was generated");
    } else {
        ESP_LOGW(TAG, "developer mode %s", on ? "ENABLED" : "off");
    }
    return save_dev_settings();
}

bool fw_dev_token_ok(const char *presented)
{
    if (!s_dev_mode || presented == NULL || s_dev_token[0] == '\0') {
        return false;
    }
    /* Both are fixed-length hex, so a differing length is not secret. */
    if (strlen(presented) != strlen(s_dev_token)) {
        return false;
    }
    /* No early exit: the time taken must not reveal how much of the token
     * matched. With 256 bits of entropy brute force is hopeless anyway, but a
     * comparison that leaks prefix length is the kind of thing that gets
     * reused somewhere it matters. */
    unsigned char diff = 0;
    for (size_t i = 0; s_dev_token[i] != '\0'; i++) {
        diff |= (unsigned char)presented[i] ^ (unsigned char)s_dev_token[i];
    }
    return diff == 0;
}

/* ======================= helpers ======================= */

static void set_state(fw_state_t st, const char *err)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_state = st;
    snprintf(s_error, sizeof(s_error), "%s", err ? err : "");
    if (st != FW_DOWNLOADING) {
        s_progress = 0;
    }
    xSemaphoreGive(s_lock);
}

/* "v1.2.3" -> {1,2,3}. Unparsable components count as 0. */
static void parse_version(const char *s, int out[3])
{
    out[0] = out[1] = out[2] = 0;
    if (s == NULL) {
        return;
    }
    if (*s == 'v' || *s == 'V') {
        s++;
    }
    for (int i = 0; i < 3; i++) {
        while (*s && !isdigit((unsigned char)*s)) {
            s++;        /* skip the separator we stopped on */
        }
        if (*s == '\0') {
            break;
        }
        out[i] = atoi(s);
        while (*s && isdigit((unsigned char)*s)) {
            s++;
        }
    }
}

/* >0 when `a` is newer than `b`. Strict, so the running build never counts as
 * an update of itself - otherwise auto-install would loop. */
static int version_cmp(const char *a, const char *b)
{
    int va[3], vb[3];
    parse_version(a, va);
    parse_version(b, vb);
    for (int i = 0; i < 3; i++) {
        if (va[i] != vb[i]) {
            return va[i] - vb[i];
        }
    }
    return 0;
}

/*
 * Keeps a redirect chain short but not so short that GitHub's does not fit:
 * api.github.com -> the asset host, and sometimes one more hop.
 */
#define FW_MAX_REDIRECTS 4

/*
 * A redirect target for a release asset is a signed object-storage URL, measured
 * at 910-930 characters for real repositories. 256 looked generous and 1024 was
 * still too tight; either would have truncated the URL into a connection error
 * with no useful explanation.
 */
#define FW_URL_MAX 2048

/*
 * Task stack. Must fit a TLS handshake (~10 KB, see the note at the create
 * call) plus the two FW_URL_MAX buffers this path keeps on the stack, with
 * room to spare so a future addition does not silently reintroduce the
 * overflow that a too-tight value caused.
 */
#define FW_TASK_STACK 16384

typedef struct {
    bool     have_location;
    char     location[FW_URL_MAX];
} redirect_capture_t;

/*
 * Captures the Location header of a 3xx reply.
 *
 * This has to be done by hand. Automatic redirects are only followed inside
 * esp_http_client_perform(), which buffers the whole body - unusable for a
 * 1.2 MB image - so the streaming open/read path has to notice a 3xx and ask
 * for the new URL itself. With disable_auto_redirect set, the client dispatches
 * the headers and nothing else.
 */
static esp_err_t fw_http_event(esp_http_client_event_t *evt)
{
    redirect_capture_t *cap = evt->user_data;
    if (cap != NULL && evt->event_id == HTTP_EVENT_ON_HEADER &&
            evt->header_key != NULL && evt->header_value != NULL &&
            strcasecmp(evt->header_key, "Location") == 0) {
        snprintf(cap->location, sizeof(cap->location), "%s", evt->header_value);
        cap->have_location = true;
    }
    return ESP_OK;
}

/*
 * One place where a request is configured, so the TLS settings cannot drift
 * between the metadata fetch and the image download. The CA bundle is what
 * makes https work at all; without it every GitHub request fails at the
 * handshake.
 *
 * `accept` is set only for asset downloads. GitHub's per-asset API endpoint
 * returns JSON metadata by default and the file itself only when asked for
 * application/octet-stream - and that endpoint matters here because the
 * friendlier browser_download_url lives on github.com, which is not always
 * reachable from this network while api.github.com is.
 */
static esp_http_client_handle_t fw_http_open(const char *url, redirect_capture_t *cap,
                                             const char *accept)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = FW_HTTP_TIMEOUT_MS,
        .disable_auto_redirect = true,   /* we follow them ourselves, see below */
        .event_handler = fw_http_event,
        .user_data = cap,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (c != NULL && accept != NULL) {
        esp_http_client_set_header(c, "Accept", accept);
    }
    return c;
}

/*
 * Follow up to FW_MAX_REDIRECTS hops, returning a client already open on a 200
 * reply (or an error). `*client_out` is always valid on success and must be
 * closed by the caller.
 *
 * HTTPS costs roughly two seconds of handshake on this chip, and each hop pays
 * it again because the redirect target is a different host. That is why the
 * default check interval is a day rather than an hour.
 */
static esp_err_t fw_http_get_open(const char *url, const char *accept,
                                  esp_http_client_handle_t *client_out,
                                  int64_t *len_out, int *status_out, char *err,
                                  size_t err_len)
{
    char cur[FW_URL_MAX];
    snprintf(cur, sizeof(cur), "%s", url);

    for (int hop = 0; hop <= FW_MAX_REDIRECTS; hop++) {
        redirect_capture_t cap = {0};
        esp_http_client_handle_t c = fw_http_open(cur, &cap, accept);
        if (c == NULL) {
            snprintf(err, err_len, "cannot create HTTP client");
            return ESP_FAIL;
        }

        if (esp_http_client_open(c, 0) != ESP_OK) {
            esp_http_client_cleanup(c);
            snprintf(err, err_len, "cannot connect");
            return ESP_FAIL;
        }

        int64_t clen = esp_http_client_fetch_headers(c);
        int status = esp_http_client_get_status_code(c);

        if (status == 200) {
            *client_out = c;
            *len_out = clen;
            if (status_out) {
                *status_out = status;
            }
            return ESP_OK;
        }

        bool is_redirect = (status == 301 || status == 302 || status == 303 ||
                            status == 307 || status == 308);
        esp_http_client_close(c);
        esp_http_client_cleanup(c);

        if (!is_redirect) {
            snprintf(err, err_len, "server returned %d", status);
            return ESP_FAIL;
        }
        if (!cap.have_location) {
            snprintf(err, err_len, "redirect %d without a Location header", status);
            return ESP_FAIL;
        }
        snprintf(cur, sizeof(cur), "%s", cap.location);
        ESP_LOGI(TAG, "redirect %d -> %s", status, cur);
    }

    snprintf(err, err_len, "too many redirects");
    return ESP_FAIL;
}

/*
 * Streamed GET into a caller buffer.
 *
 * esp_http_client_perform() (used by the DoH relay) would work for the small
 * documents but not for the 1.2 MB image, so everything here uses the
 * open/fetch_headers/read form and one code path serves both.
 */
static esp_err_t http_get_to_buf(const char *url, char *buf, size_t cap,
                                 size_t *out_len, int *status_out, char *err,
                                 size_t err_len)
{
    esp_http_client_handle_t c = NULL;
    int64_t clen = 0;
    if (fw_http_get_open(url, NULL, &c, &clen, status_out, err, err_len) != ESP_OK) {
        return ESP_FAIL;
    }

    esp_err_t ret = ESP_FAIL;
    /*
     * esp_http_client_fetch_headers returns 0 when the reply has no
     * content-length header *or* is chunked - and chunked is exactly what this
     * server sends. So 0 means "length unknown", never "empty": comparing
     * against it as though it were a real length made every check fail with
     * "short read (N of 0 bytes)".
     */
    if (clen > (int64_t)cap) {
        snprintf(err, err_len, "response is %d bytes, over the %u byte limit",
                 (int)clen, (unsigned)cap);
        goto done;
    }

    /* One byte is held back for the terminator. */
    size_t total = 0;
    int r;
    while ((r = esp_http_client_read(c, buf + total, cap - 1 - total)) > 0) {
        total += (size_t)r;
        if (total >= cap - 1) {
            break;
        }
    }
    if (r < 0) {
        snprintf(err, err_len, "read failed");
        goto done;
    }
    /*
     * With no content-length to lean on, this is the only thing that separates
     * a complete reply from one that filled the buffer. It has to be an error
     * rather than a silent trim: the field this document is read for, tag_name,
     * sits after the release notes, so a truncated reply parses cleanly and
     * simply looks like "no newer version".
     */
    if (!esp_http_client_is_complete_data_received(c)) {
        snprintf(err, err_len, "response is larger than %u bytes", (unsigned)cap);
        goto done;
    }
    if (clen > 0 && (int64_t)total != clen) {
        snprintf(err, err_len, "short read (%u of %d bytes)",
                 (unsigned)total, (int)clen);
        goto done;
    }

    buf[total] = '\0';
    *out_len = total;
    ret = ESP_OK;

done:
    esp_http_client_close(c);
    esp_http_client_cleanup(c);
    return ret;
}

/* Feed one release asset URL through the hashing OTA writer. */
static esp_err_t ota_stream_url(const char *url, esp_ota_handle_t handle,
                                uint8_t digest_out[32], size_t expected,
                                fw_ota_result_t *result, char *err, size_t err_len)
{
    esp_http_client_handle_t c = NULL;
    int64_t clen = 0;
    /* Asks GitHub's asset endpoint for the bytes rather than its JSON metadata;
     * harmless for a plain file server. */
    if (fw_http_get_open(url, "application/octet-stream", &c, &clen, NULL,
                         err, err_len) != ESP_OK) {
        return ESP_FAIL;
    }

    esp_err_t ret = ESP_FAIL;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    bool hashing = false;
    char *buf = NULL;
    size_t total = 0;

    if (clen > 0 && (size_t)clen != expected) {
        /* The release metadata said one size and the file says another; trust
         * neither and stop before writing. */
        snprintf(err, err_len, "size mismatch: release says %u, file says %d",
                 (unsigned)expected, (int)clen);
        goto done;
    }

    /* Internal RAM on purpose: esp_ota_write disables the flash cache, and
     * PSRAM lives behind that cache. */
    buf = heap_caps_malloc(FW_OTA_CHUNK, MALLOC_CAP_INTERNAL);
    if (buf == NULL) {
        snprintf(err, err_len, "out of memory");
        goto done;
    }

    if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        snprintf(err, err_len, "cannot start the checksum");
        goto done;
    }
    hashing = true;

    for (;;) {
        int r = esp_http_client_read(c, buf, FW_OTA_CHUNK);
        if (r < 0) {
            snprintf(err, err_len, "download failed after %u bytes", (unsigned)total);
            goto done;
        }
        if (r == 0) {
            break;
        }
        if (psa_hash_update(&op, (const uint8_t *)buf, (size_t)r) != PSA_SUCCESS) {
            snprintf(err, err_len, "checksum update failed");
            goto done;
        }
        esp_err_t werr = esp_ota_write(handle, buf, (size_t)r);
        if (werr != ESP_OK) {
            if (fw_ota_err_is_bad_image(werr)) {
                *result = FW_OTA_BAD_IMAGE;
                snprintf(err, err_len, "%s", fw_ota_result_text(FW_OTA_BAD_IMAGE));
            } else {
                *result = FW_OTA_WRITE_FAILED;
                snprintf(err, err_len, "%s", fw_ota_result_text(FW_OTA_WRITE_FAILED));
            }
            goto done;
        }
        total += (size_t)r;
        if (expected > 0) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_progress = (int)((total * 100) / expected);
            xSemaphoreGive(s_lock);
        }
    }

    /* clen is 0 for a chunked reply, i.e. unknown; the authoritative check is
     * the one against the size the release metadata declared. */
    if (clen > 0 && total != (size_t)clen) {
        snprintf(err, err_len, "short download (%u of %d bytes)",
                 (unsigned)total, (int)clen);
        goto done;
    }
    if (total != expected) {
        snprintf(err, err_len, "downloaded %u bytes, expected %u",
                 (unsigned)total, (unsigned)expected);
        goto done;
    }

    size_t olen = 0;
    if (psa_hash_finish(&op, digest_out, 32, &olen) != PSA_SUCCESS || olen != 32) {
        hashing = false;
        snprintf(err, err_len, "cannot finish the checksum");
        goto done;
    }
    hashing = false;
    *result = FW_OTA_OK;
    ret = ESP_OK;

done:
    if (hashing) {
        psa_hash_abort(&op);
    }
    free(buf);
    esp_http_client_close(c);
    esp_http_client_cleanup(c);
    return ret;
}

/* ======================= check ======================= */

/*
 * Reduce a repository reference to "owner/repo", lowercase.
 *
 * Both sides of the comparison need the same shape: a feed URL is an API path
 * (`.../repos/owner/repo/releases/latest`, on GitHub or Gitea) while the build
 * origin is a clone URL (`https://host/owner/repo.git` or
 * `git@host:owner/repo`). Comparing those two strings directly would never
 * match, and the mismatch would look like a bug in the guard rather than the
 * point of it.
 *
 * Returns false when nothing identifiable is present.
 */
static bool repo_identity(const char *url, char *out, size_t out_len)
{
    if (url == NULL || out_len == 0) {
        return false;
    }
    out[0] = '\0';

    /* Skip any scheme, and turn git@host:owner/repo into host/owner/repo. */
    const char *p = url;
    const char *colon = NULL;
    for (const char *q = url; *q; q++) {
        if (*q == '/' || *q == ':') {
            colon = q;
            break;
        }
    }
    const char *scheme_end = strstr(url, "://");
    if (scheme_end != NULL) {
        p = scheme_end + 3;
    } else if (colon != NULL && colon > url && colon[-1] != '/') {
        p = url;   /* scp-like: git@host:owner/repo */
    }

    /* Copy the path, dropping query and fragment, so it can be split. */
    char path[FW_URL_MAX];
    snprintf(path, sizeof(path), "%s", p);
    for (char *c = path; *c; c++) {
        if (*c == '?' || *c == '#') {
            *c = '\0';
            break;
        }
    }

    /* Collect up to 8 path segments after turning ':' separators into '/'. */
    char *seg[8];
    int nseg = 0;
    for (char *c = path; *c && nseg < 8; ) {
        while (*c == '/' || *c == ':') {
            *c++ = '\0';
        }
        if (*c == '\0') {
            break;
        }
        seg[nseg++] = c;
        while (*c && *c != '/' && *c != ':') {
            c++;
        }
    }
    if (nseg < 2) {
        return false;
    }

    /* Drop a ".git" suffix and any trailing "releases/..." or "tags/...". */
    size_t last = strlen(seg[nseg - 1]);
    if (last > 4 && strcasecmp(seg[nseg - 1] + last - 4, ".git") == 0) {
        seg[nseg - 1][last - 4] = '\0';
    }
    for (int i = 0; i < nseg; i++) {
        if (strcasecmp(seg[i], "releases") == 0 || strcasecmp(seg[i], "tags") == 0) {
            nseg = i;
            break;
        }
    }
    /*
     * An API path has a "repos" segment and the owner/repo follow it; a clone
     * URL has neither, and owner/repo are the LAST two segments. Defaulting to
     * the last two and only overriding on "repos" is what makes
     * https://host/owner/repo.git comparable with
     * https://api.host/repos/owner/repo/releases/latest - taking the first two
     * instead would yield "host/owner", which never matches anything.
     */
    int from = nseg - 2;
    for (int i = 0; i < nseg; i++) {
        if (strcasecmp(seg[i], "repos") == 0 && nseg - (i + 1) >= 2) {
            from = i + 1;
            break;
        }
    }

    snprintf(out, out_len, "%s/%s", seg[from], seg[from + 1]);
    for (char *c = out; *c; c++) {
        *c = (char)tolower((unsigned char)*c);
    }
    return true;
}

/*
 * May this firmware install what the configured feed serves?
 *
 * The feed and the build must belong to the same repository. A fork carries its
 * own origin, so the default feed - upstream - stops being an update and
 * becomes someone else's firmware, which is exactly the mistake worth refusing.
 * A user who really wants to track upstream can change the feed to match, which
 * is a deliberate act rather than a default.
 */
static bool feed_matches_build(const char *feed_url, char *feed_id, size_t feed_len)
{
    char build_id[128];
    bool have_feed = repo_identity(feed_url, feed_id, feed_len);
    bool have_build = repo_identity(FW_BUILD_REPO, build_id, sizeof(build_id));

    if (!have_feed || !have_build) {
        return false;
    }
    return strcmp(feed_id, build_id) == 0;
}

/*
 * Where to fetch one release asset from.
 *
 * GitHub offers two addresses per asset and they are not equivalent on this
 * network. `browser_download_url` points at github.com, whose web front end may
 * be blocked while api.github.com still answers. The per-asset API `url` stays
 * on api.github.com and redirects to signed object storage - one extra hop, and
 * it works when the other does not. So prefer it, but only for GitHub: other
 * servers (a Gitea mirror) expose a `url` with different semantics that returns
 * JSON metadata rather than the file.
 */
static const char *asset_fetch_url(const cJSON *asset)
{
    static const char GH_API[] = "https://api.github.com/";

    const cJSON *u = cJSON_GetObjectItemCaseSensitive(asset, "url");
    if (cJSON_IsString(u) && u->valuestring != NULL &&
            strncmp(u->valuestring, GH_API, sizeof(GH_API) - 1) == 0) {
        return u->valuestring;
    }

    const cJSON *b = cJSON_GetObjectItemCaseSensitive(asset, "browser_download_url");
    if (cJSON_IsString(b) && b->valuestring != NULL) {
        return b->valuestring;
    }
    return NULL;
}

static esp_err_t do_check(void)
{
    set_state(FW_CHECKING, NULL);

    char url[256];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    snprintf(url, sizeof(url), "%s", s_url);
    xSemaphoreGive(s_lock);

    /*
     * Refuse a feed that is not this build's own repository. Doing it here
     * rather than at install time means the panel explains it on the check
     * - the user sees why nothing is happening instead of finding that the
     * install button quietly does nothing.
     */
    {
        char feed_id[128];
        if (!feed_matches_build(url, feed_id, sizeof(feed_id))) {
            /* Sized for the identity embedded above, not for a typical one:
             * snprintf is checked against the declared size, and -Werror turns
             * a possible truncation into a build failure. */
            char msg[FW_ERR_MAX];
            if (FW_BUILD_REPO[0] == '\0') {
                snprintf(msg, sizeof(msg), "built without a repository; "
                                           "set the feed for your own");
            } else {
                snprintf(msg, sizeof(msg), "feed is '%s', this firmware is not",
                         feed_id[0] ? feed_id : "unrecognised");
            }
            ESP_LOGW(TAG, "refusing feed: %s", msg);
            set_state(FW_ERROR, msg);
            return ESP_FAIL;
        }
    }

    char *json = malloc(FW_JSON_MAX);
    if (json == NULL) {
        set_state(FW_ERROR, "out of memory");
        return ESP_ERR_NO_MEM;
    }

    char err[96] = {0};
    size_t n = 0;
    int status = 0;
    esp_err_t err_code = http_get_to_buf(url, json, FW_JSON_MAX - 1, &n, &status,
                                         err, sizeof(err));
    if (err_code != ESP_OK) {
        ESP_LOGW(TAG, "check failed: %s", err);
        free(json);
        set_state(FW_ERROR, err);
        return ESP_FAIL;
    }

    cJSON *root = cJSON_Parse(json);
    free(json);
    if (root == NULL) {
        set_state(FW_ERROR, "server reply was not JSON");
        return ESP_FAIL;
    }

    esp_err_t ret = ESP_FAIL;
    const cJSON *tag = cJSON_GetObjectItemCaseSensitive(root, "tag_name");
    if (!cJSON_IsString(tag) || tag->valuestring == NULL) {
        set_state(FW_ERROR, "no version in the release");
        goto out;
    }

    /* Only ever the application image. The release also carries a merged
     * full-flash image, and writing that into an app slot would fail - or, with
     * a different layout, not fail until boot. Matching the name exactly is the
     * cheap way to never make that mistake. */
    const cJSON *dl = NULL, *sha = NULL, *assets = cJSON_GetObjectItem(root, "assets");
    const cJSON *a = NULL;
    cJSON_ArrayForEach(a, assets) {
        const cJSON *nm = cJSON_GetObjectItemCaseSensitive(a, "name");
        if (!cJSON_IsString(nm) || nm->valuestring == NULL) {
            continue;
        }
        if (strcmp(nm->valuestring, "embedwrt.bin") == 0) {
            dl = a;
        } else if (strcmp(nm->valuestring, "embedwrt.bin.sha256") == 0) {
            sha = a;
        }
    }
    if (dl == NULL) {
        set_state(FW_ERROR, "release has no embedwrt.bin asset");
        goto out;
    }
    if (sha == NULL) {
        /* Without the checksum the image cannot be verified, and an unverified
         * image is not something to flash. Refuse rather than skip the check. */
        set_state(FW_ERROR, "release has no embedwrt.bin.sha256 asset");
        goto out;
    }

    const char *dl_url = asset_fetch_url(dl);
    const char *sha_url = asset_fetch_url(sha);
    const cJSON *size = cJSON_GetObjectItemCaseSensitive(dl, "size");
    if (dl_url == NULL || sha_url == NULL ||
            !cJSON_IsNumber(size) || size->valuedouble <= 0) {
        set_state(FW_ERROR, "release metadata is incomplete");
        goto out;
    }

    {
        const char *running = esp_app_get_description()->version;
        int cmp = version_cmp(tag->valuestring, running);
        ESP_LOGI(TAG, "latest is %s, running %s", tag->valuestring, running);

        xSemaphoreTake(s_lock, portMAX_DELAY);
        snprintf(s_latest, sizeof(s_latest), "%s",
                 tag->valuestring[0] == 'v' ? tag->valuestring + 1 : tag->valuestring);
        s_last_check_us = esp_timer_get_time();
        s_error[0] = '\0';
        if (cmp > 0) {
            snprintf(s_dl_url, sizeof(s_dl_url), "%s", dl_url);
            snprintf(s_sha_url, sizeof(s_sha_url), "%s", sha_url);
            s_img_size = (size_t)size->valuedouble;
            s_state = FW_AVAILABLE;
        } else {
            /* Drop the previous offer so a later install request cannot act on
             * a version this check just declared unnecessary. do_install also
             * guards on the state, but leaving stale URLs around invites the
             * kind of bug where only one of the two guards is correct. */
            s_dl_url[0] = '\0';
            s_sha_url[0] = '\0';
            s_img_size = 0;
            s_state = FW_UP_TO_DATE;
        }
        xSemaphoreGive(s_lock);

        ret = (cmp > 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
    }

out:
    cJSON_Delete(root);
    return ret;
}

/* ======================= install ======================= */

static esp_err_t do_install(void)
{
    char dl_url[256], sha_url[256], ver[32];
    size_t size;
    uint8_t expect[32];

    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool have = (s_state == FW_AVAILABLE);
    snprintf(dl_url, sizeof(dl_url), "%s", s_dl_url);
    snprintf(sha_url, sizeof(sha_url), "%s", s_sha_url);
    snprintf(ver, sizeof(ver), "%s", s_latest);
    size = s_img_size;
    xSemaphoreGive(s_lock);

    if (!have) {
        return ESP_ERR_INVALID_STATE;
    }

    char err[96] = {0};

    /* The checksum first: it is tiny, and fetching it before the image means a
     * release whose checksum is unreachable costs nothing. */
    char sbuf[256];
    size_t sn = 0;
    int status = 0;
    if (http_get_to_buf(sha_url, sbuf, sizeof(sbuf) - 1, &sn, &status, err, sizeof(err)) != ESP_OK) {
        ESP_LOGW(TAG, "cannot fetch the checksum: %s", err);
        set_state(FW_ERROR, err);
        return ESP_FAIL;
    }

    /* `<hex>  <filename>`; only the first field matters. */
    int nib = 0;
    memset(expect, 0, sizeof(expect));
    for (const char *p = sbuf; *p && nib < 64; p++) {
        int v;
        if (*p >= '0' && *p <= '9') {
            v = *p - '0';
        } else if (*p >= 'a' && *p <= 'f') {
            v = *p - 'a' + 10;
        } else if (*p >= 'A' && *p <= 'F') {
            v = *p - 'A' + 10;
        } else if (nib == 0) {
            continue;   /* leading whitespace */
        } else {
            break;      /* end of the hex field */
        }
        expect[nib / 2] = (uint8_t)((expect[nib / 2] << 4) | v);
        nib++;
    }
    if (nib != 64) {
        set_state(FW_ERROR, "checksum file is malformed");
        return ESP_FAIL;
    }

    set_state(FW_DOWNLOADING, NULL);
    ESP_LOGW(TAG, "downloading %s (%u bytes)", ver, (unsigned)size);

    const esp_partition_t *part = NULL;
    esp_ota_handle_t handle = 0;
    esp_err_t berr = fw_ota_begin(size, &part, &handle);
    if (berr != ESP_OK) {
        set_state(FW_ERROR, berr == ESP_ERR_INVALID_SIZE ? "image is larger than the OTA slot"
                                                         : "cannot start the update");
        return berr;
    }

    fw_ota_result_t res = FW_OTA_OK;
    uint8_t digest[32];
    if (ota_stream_url(dl_url, handle, digest, size, &res, err, sizeof(err)) != ESP_OK) {
        fw_ota_abort(handle);
        ESP_LOGE(TAG, "download failed: %s", err);
        set_state(FW_ERROR, err);
        return ESP_FAIL;
    }

    /* Verify before esp_ota_end: once end has run there is no abort left, and
     * the whole point is that a bad image must not reach the boot partition. */
    if (memcmp(digest, expect, 32) != 0) {
        fw_ota_abort(handle);
        ESP_LOGE(TAG, "checksum mismatch - refusing to install");
        set_state(FW_ERROR, "checksum mismatch");
        return ESP_ERR_INVALID_CRC;
    }
    ESP_LOGI(TAG, "checksum ok");

    set_state(FW_INSTALLING, NULL);
    char newver[32] = {0};
    fw_ota_result_t fin = fw_ota_finish(handle, part, newver, sizeof(newver));
    if (fin != FW_OTA_OK) {
        set_state(FW_ERROR, fw_ota_result_text(fin));
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "%s installed into %s; restarting", newver, part->label);
    set_state(FW_IDLE, NULL);
    fw_schedule_reboot();
    return ESP_OK;
}

/* ======================= task ======================= */

esp_err_t fw_update_check_now(void)
{
    xEventGroupSetBits(s_eg, UPD_CHECK_BIT);
    return ESP_OK;
}

esp_err_t fw_update_install_now(void)
{
    xEventGroupSetBits(s_eg, UPD_INSTALL_BIT);
    return ESP_OK;
}

void fw_update_status(fw_status_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    out->state = s_state;
    out->interval_hours = s_interval_hours;
    out->auto_install = s_auto_install;
    snprintf(out->latest, sizeof(out->latest), "%s", s_latest);
    snprintf(out->error, sizeof(out->error), "%s", s_error);
    snprintf(out->url, sizeof(out->url), "%s", s_url);
    out->progress = s_progress;
    out->last_check_us = s_last_check_us;
    xSemaphoreGive(s_lock);

    const esp_app_desc_t *d = esp_app_get_description();
    snprintf(out->running, sizeof(out->running), "%s", d ? d->version : "");
    const esp_partition_t *run = esp_ota_get_running_partition();
    snprintf(out->slot, sizeof(out->slot), "%s", run ? run->label : "");

    out->modified = FW_BUILD_DIRTY;
    if (!repo_identity(FW_BUILD_REPO, out->build_repo, sizeof(out->build_repo))) {
        out->build_repo[0] = '\0';
    }
}

static void fw_update_task(void *arg)
{
    bool first_check_done = false;

    for (;;) {
        /* Nothing to do without an address. The router tells us when that
         * changes rather than us reaching into its event group. */
        xEventGroupWaitBits(s_eg, UPD_ONLINE_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

        uint32_t hours;
        xSemaphoreTake(s_lock, portMAX_DELAY);
        hours = s_interval_hours;
        xSemaphoreGive(s_lock);

        /* Shortly after boot, check once regardless of the interval: a device
         * that was just flashed or power-cycled should not sit for a day before
         * it can report that an update exists. Skipped when checks are off, so
         * "off" really means no unsolicited traffic. */
        TickType_t wait;
        bool will_check;
        if (!first_check_done && hours > 0) {
            wait = pdMS_TO_TICKS(2 * 60 * 1000);
            will_check = true;
        } else if (hours == 0) {
            wait = pdMS_TO_TICKS(30 * 1000);
            will_check = false;
        } else {
            wait = pdMS_TO_TICKS((uint64_t)hours * 3600ULL * 1000ULL);
            will_check = true;
        }

        EventBits_t bits = xEventGroupWaitBits(s_eg, UPD_CHECK_BIT | UPD_INSTALL_BIT,
                                               pdTRUE, pdFALSE, wait);
        if (bits & UPD_INSTALL_BIT) {
            do_install();
            continue;
        }

        bool explicit_check = (bits & UPD_CHECK_BIT) != 0;
        if (!explicit_check && !will_check) {
            continue;   /* interval is off and nobody asked */
        }

        esp_err_t found = do_check();
        first_check_done = true;

        bool auto_on;
        xSemaphoreTake(s_lock, portMAX_DELAY);
        auto_on = s_auto_install;
        xSemaphoreGive(s_lock);

        if (found == ESP_OK && auto_on) {
            ESP_LOGW(TAG, "auto-install is on and a newer version exists");
            do_install();
        }
    }
}

/* ======================= init ======================= */

void fw_update_init(void)
{
    if (s_lock != NULL) {
        return;
    }
    s_lock = xSemaphoreCreateMutex();
    s_eg = xEventGroupCreate();
    if (s_lock == NULL || s_eg == NULL) {
        ESP_LOGE(TAG, "cannot create the sync primitives");
        return;
    }

    load_settings();

    /* Idempotent, and esp-tls may already have done it. Called here so hashing
     * does not depend on whether a TLS connection happened to come first. */
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed (%d); checksum verification is unavailable",
                 (int)ps);
    }

    /*
     * Priority below the reconnect task: a firmware check must never delay
     * bringing the link back up.
     *
     * The stack has to cover a TLS handshake, which on this chip is around
     * 10 KB of software big-integer arithmetic - the DoH relay uses 10240 for
     * exactly that reason. This task was originally 8192 because the update
     * feed was plain HTTP on the LAN and no handshake ever happened; moving to
     * an HTTPS feed without revisiting it overflowed the stack, and the device
     * rebooted partway through every check. On top of the handshake this path
     * also holds the redirect buffers (see FW_URL_MAX), so the total is
     * deliberately well past the DoH figure rather than merely equal to it.
     */
    if (xTaskCreate(fw_update_task, "fw_update", FW_TASK_STACK, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "cannot create the update task");
    } else {
        ESP_LOGI(TAG, "auto-update from %s", s_url);
    }
}
