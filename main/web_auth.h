/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Panel authentication and roles.
 *
 * Replaces the earlier HTTP Basic scheme. Basic worked but could not log out:
 * browsers cache the credential for the realm and re-send it on every request,
 * so "log out" was impossible to implement honestly. A login form plus a session
 * cookie fixes that, and it is also what makes a guest role possible at all.
 *
 * Two roles:
 *
 *   ADMIN  - full access, granted by logging in.
 *   GUEST  - unauthenticated. Sees only its own device and the devices it owns;
 *            cannot reach the admin-only routes at all.
 *
 * Guest identity comes from the request's source address, mapped back to a MAC
 * through the DHCP lease table, because an HTTP request carries no other
 * identity. A guest reaching the panel from outside the AP subnet (a device on
 * the upstream LAN, whose address is not in that table) therefore has no
 * identity and sees nothing until it logs in - which is the correct outcome, not
 * a gap: it has no device on this AP to own.
 *
 * IMPORTANT, and not hidden: there is no TLS on this panel, so the session
 * cookie travels in clear exactly as the Basic credential did. What this buys is
 * a working login/logout and a role model, NOT confidentiality. Adding TLS would
 * need a certificate the browser already trusts, which a self-signed one is not.
 *
 * Backward compatibility: with no admin password set, every request is treated
 * as ADMIN. That is exactly the behaviour before roles existed, so a device that
 * has never been given a password stays open rather than silently becoming
 * guest-only.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_http_server.h"

typedef enum {
    WEB_ROLE_ADMIN = 0,
    WEB_ROLE_GUEST,
} web_role_t;

#define WEB_USER_MAX   32
#define WEB_PASS_MAX   64
#define WEB_TOKEN_LEN  32          /* hex characters, so 16 random bytes */

void web_auth_init(void);

/* True when an admin password has been set. False means everyone is ADMIN. */
bool web_auth_enabled(void);

const char *web_auth_user(void);

/* Empty password disables authentication entirely. Returns ESP_ERR_INVALID_ARG
 * for a password that is too short, too long, or a username containing ':'. */
esp_err_t web_auth_set_credentials(const char *user, const char *pass);

/* Verify credentials and open a session. On success writes the cookie value
 * (NUL-terminated, WEB_TOKEN_LEN+1 bytes required) into token_out. */
esp_err_t web_auth_login(const char *user, const char *pass,
                         char *token_out, size_t cap);

/* Invalidate the session named by the request's cookie, if any. */
void web_auth_logout(httpd_req_t *req);

/* The role this request should be served as. */
web_role_t web_auth_role_of(httpd_req_t *req);

/* The requesting client's address, derived from its socket. Network order.
 * False when it cannot be determined. */
bool web_auth_client_ip(httpd_req_t *req, uint32_t *ip_out);

#define WEB_AUTH_COOKIE_NAME  "sess"

/*
 * Build the Set-Cookie VALUE for a session token into `out`.
 *
 * The caller must keep `out` alive until the response has been sent, because
 * httpd_resp_set_hdr() stores the pointer rather than copying it. Passing a
 * buffer that goes out of scope before httpd_resp_send() makes the header get
 * written from reused stack - which produced a Set-Cookie of binary garbage
 * until this was spotted. A string literal is safe; a local buffer is only safe
 * if the send happens before the function returns.
 */
void web_auth_cookie_for(const char *token, char *out, size_t cap);

/* A literal, so it may be passed straight to httpd_resp_set_hdr(). */
#define WEB_AUTH_COOKIE_CLEAR \
    WEB_AUTH_COOKIE_NAME "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

/* Session lifetime, exposed so the UI can say something truthful about it. */
int web_auth_session_seconds(void);
