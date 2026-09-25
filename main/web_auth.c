/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "nvs.h"

#include "web_auth.h"

#define NVS_NAMESPACE "storage"
#define NVS_KEY_USER  "web_user"
#define NVS_KEY_PASS  "web_pass"
#define COOKIE_NAME   "sess"

/* A handful of concurrent sessions is plenty for a panel on a LAN, and a fixed
 * table keeps this free of allocation. */
#define SESSION_MAX   4
#define SESSION_TTL_MS (12 * 60 * 60 * 1000)   /* 12 hours */

static const char *TAG = "web_auth";

typedef struct {
    bool    used;
    char    token[WEB_TOKEN_LEN + 1];
    int64_t expires_ms;
} session_t;

static char s_user[WEB_USER_MAX + 1] = "admin";
static char s_pass[WEB_PASS_MAX + 1] = "";     /* empty => authentication disabled */
static session_t s_sessions[SESSION_MAX];
static SemaphoreHandle_t s_lock;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

/* Caller must hold s_lock. */
static void expire_locked(void)
{
    int64_t t = now_ms();
    for (int i = 0; i < SESSION_MAX; i++) {
        if (s_sessions[i].used && t >= s_sessions[i].expires_ms) {
            s_sessions[i].used = false;
        }
    }
}

/* Caller must hold s_lock. */
static session_t *find_locked(const char *token)
{
    if (token == NULL || token[0] == '\0') {
        return NULL;
    }
    for (int i = 0; i < SESSION_MAX; i++) {
        if (s_sessions[i].used && strcmp(s_sessions[i].token, token) == 0) {
            return &s_sessions[i];
        }
    }
    return NULL;
}

void web_auth_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(s_user);
        if (nvs_get_str(h, NVS_KEY_USER, s_user, &len) != ESP_OK || s_user[0] == '\0') {
            strncpy(s_user, "admin", sizeof(s_user) - 1);
        }
        len = sizeof(s_pass);
        nvs_get_str(h, NVS_KEY_PASS, s_pass, &len);
        nvs_close(h);
    }
    memset(s_sessions, 0, sizeof(s_sessions));

    if (s_pass[0] == '\0') {
        ESP_LOGW(TAG, "no admin password set: every request is treated as admin "
                      "and the panel is OPEN to anyone who can reach it");
    } else {
        ESP_LOGI(TAG, "panel requires login, user '%s', sessions last %d h",
                 s_user, SESSION_TTL_MS / 3600000);
    }
}

bool web_auth_enabled(void)
{
    return s_pass[0] != '\0';
}

const char *web_auth_user(void)
{
    return s_user;
}

int web_auth_session_seconds(void)
{
    return SESSION_TTL_MS / 1000;
}

esp_err_t web_auth_set_credentials(const char *user, const char *pass)
{
    if (user == NULL || pass == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t ul = strlen(user), pl = strlen(pass);

    if (pl == 0) {
        /* Disabling is deliberate: clear the password and drop every session,
         * since with authentication off the sessions mean nothing. */
        s_pass[0] = '\0';
        if (s_lock != NULL) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            memset(s_sessions, 0, sizeof(s_sessions));
            xSemaphoreGive(s_lock);
        }
        nvs_handle_t h;
        if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
            nvs_set_str(h, NVS_KEY_PASS, "");
            nvs_commit(h);
            nvs_close(h);
        }
        ESP_LOGW(TAG, "authentication disabled: the panel is now OPEN");
        return ESP_OK;
    }

    if (pl < 8 || pl > WEB_PASS_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (ul == 0 || ul > WEB_USER_MAX || strchr(user, ':') != NULL ||
            strchr(user, '"') != NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    strncpy(s_user, user, sizeof(s_user) - 1);
    s_user[sizeof(s_user) - 1] = '\0';
    strncpy(s_pass, pass, sizeof(s_pass) - 1);
    s_pass[sizeof(s_pass) - 1] = '\0';

    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return ESP_FAIL;
    }
    nvs_set_str(h, NVS_KEY_USER, s_user);
    nvs_set_str(h, NVS_KEY_PASS, s_pass);
    nvs_commit(h);
    nvs_close(h);

    /* Changing the password must not leave old sessions alive. */
    if (s_lock != NULL) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        memset(s_sessions, 0, sizeof(s_sessions));
        xSemaphoreGive(s_lock);
    }
    ESP_LOGI(TAG, "credentials updated, user '%s', all sessions dropped", s_user);
    return ESP_OK;
}

esp_err_t web_auth_login(const char *user, const char *pass,
                         char *token_out, size_t cap)
{
    if (user == NULL || pass == NULL || token_out == NULL || cap < WEB_TOKEN_LEN + 1) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!web_auth_enabled()) {
        return ESP_ERR_INVALID_STATE;   /* nothing to log into */
    }
    /* Not constant-time, deliberately: the password arrives in the clear in the
     * POST body of this same unencrypted connection, so a timing side channel
     * would reveal nothing an observer could not simply read. */
    if (strcmp(user, s_user) != 0 || strcmp(pass, s_pass) != 0) {
        ESP_LOGW(TAG, "failed login for user '%s'", user);
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t raw[WEB_TOKEN_LEN / 2];
    esp_fill_random(raw, sizeof(raw));
    char token[WEB_TOKEN_LEN + 1];
    for (size_t i = 0; i < sizeof(raw); i++) {
        snprintf(token + i * 2, 3, "%02x", raw[i]);
    }

    if (s_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    expire_locked();
    session_t *slot = NULL;
    for (int i = 0; i < SESSION_MAX; i++) {
        if (!s_sessions[i].used) {
            slot = &s_sessions[i];
            break;
        }
    }
    if (slot == NULL) {
        /* Full: evict the one expiring soonest rather than refusing the login. */
        slot = &s_sessions[0];
        for (int i = 1; i < SESSION_MAX; i++) {
            if (s_sessions[i].expires_ms < slot->expires_ms) {
                slot = &s_sessions[i];
            }
        }
        ESP_LOGW(TAG, "session table full, evicting the oldest");
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    snprintf(slot->token, sizeof(slot->token), "%s", token);
    slot->expires_ms = now_ms() + SESSION_TTL_MS;
    xSemaphoreGive(s_lock);

    snprintf(token_out, cap, "%s", token);
    ESP_LOGI(TAG, "login ok for '%s'", user);
    return ESP_OK;
}

void web_auth_logout(httpd_req_t *req)
{
    char token[WEB_TOKEN_LEN + 1] = {0};
    size_t len = sizeof(token);
    if (httpd_req_get_cookie_val(req, COOKIE_NAME, token, &len) != ESP_OK) {
        return;
    }
    if (s_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    session_t *s = find_locked(token);
    if (s != NULL) {
        s->used = false;
    }
    xSemaphoreGive(s_lock);
}

web_role_t web_auth_role_of(httpd_req_t *req)
{
    /* No password set means the panel behaves exactly as it did before roles
     * existed: everyone is an administrator. */
    if (!web_auth_enabled()) {
        return WEB_ROLE_ADMIN;
    }
    char token[WEB_TOKEN_LEN + 1] = {0};
    size_t len = sizeof(token);
    if (httpd_req_get_cookie_val(req, COOKIE_NAME, token, &len) != ESP_OK) {
        return WEB_ROLE_GUEST;
    }
    if (s_lock == NULL) {
        return WEB_ROLE_GUEST;
    }

    web_role_t role = WEB_ROLE_GUEST;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    expire_locked();
    session_t *s = find_locked(token);
    if (s != NULL) {
        /* Sliding expiry: an active user is not logged out mid-session. */
        s->expires_ms = now_ms() + SESSION_TTL_MS;
        role = WEB_ROLE_ADMIN;
    }
    xSemaphoreGive(s_lock);
    return role;
}

bool web_auth_client_ip(httpd_req_t *req, uint32_t *ip_out)
{
    if (req == NULL || ip_out == NULL) {
        return false;
    }
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0) {
        return false;
    }

    /*
     * The peer may come back as an IPv4-mapped IPv6 address (family AF_INET6,
     * "::ffff:a.b.c.d") rather than a plain AF_INET one, because the server's
     * socket ends up dual-stack. Checking only for AF_INET here rejected every
     * request, so no caller ever had an identity - which surfaced as guests
     * seeing "this address is not a device on this network" no matter what they
     * connected from. Both forms are handled now; a genuine IPv6 peer is not,
     * since subscribers on this AP are IPv4 and cannot be mapped to a MAC.
     */
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) {
        ESP_LOGW(TAG, "getpeername failed: errno=%d", errno);
        return false;
    }

    if (ss.ss_family == AF_INET) {
        *ip_out = ((struct sockaddr_in *)&ss)->sin_addr.s_addr;
        return true;
    }
    if (ss.ss_family == AF_INET6) {
        const uint8_t *b = ((struct sockaddr_in6 *)&ss)->sin6_addr.s6_addr;
        static const uint8_t v4map[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (slen >= sizeof(struct sockaddr_in6) && memcmp(b, v4map, sizeof(v4map)) == 0) {
            memcpy(ip_out, b + 12, 4);
            return true;
        }
        ESP_LOGD(TAG, "peer is a real IPv6 address; cannot map it to a client");
        return false;
    }
    return false;
}

void web_auth_cookie_for(const char *token, char *out, size_t cap)
{
    /* No Secure attribute: this panel is HTTP only, so marking the cookie Secure
     * would stop the browser sending it at all. HttpOnly keeps it away from
     * scripts, and SameSite=Lax keeps it off cross-site requests. */
    if (out == NULL || cap == 0) {
        return;
    }
    snprintf(out, cap,
             "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d",
             WEB_AUTH_COOKIE_NAME, token ? token : "", web_auth_session_seconds());
}
