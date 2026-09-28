/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Firmware update: the OTA primitives, plus a background task that discovers
 * new releases on a Gitea instance and can install them.
 *
 * Two ways in, one write path. The panel can accept an uploaded image, and the
 * task can pull one from the network; both go through fw_ota_begin/finish
 * below. That sequence decides which partition the device boots next, so having
 * a single copy of it is not tidiness - two copies would drift, and a drifted
 * copy means a device that will not boot.
 *
 * Failure safety, which both callers rely on: the boot partition is switched
 * only after the image has been fully written and accepted. Anything that goes
 * wrong before that leaves the running firmware untouched and merely wastes the
 * inactive slot.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

/*
 * Flash is written in chunks this size. The buffer must live in internal RAM:
 * esp_ota_write runs with the flash cache disabled, and on this chip PSRAM is
 * only reachable through that cache.
 */
#define FW_OTA_CHUNK 4096

/* Why an OTA ended, so each caller can present it its own way: the HTTP
 * handler answers with a status code, the updater records it in its status. */
typedef enum {
    FW_OTA_OK = 0,
    FW_OTA_NO_SLOT,          /* no inactive partition to write to */
    FW_OTA_TOO_BIG,          /* image does not fit the slot */
    FW_OTA_BEGIN_FAILED,
    FW_OTA_WRITE_FAILED,     /* flash write rejected the bytes */
    FW_OTA_BAD_IMAGE,        /* the bytes are not an app image at all */
    FW_OTA_NO_DESCRIPTOR,    /* no app descriptor inside the image */
    FW_OTA_WRONG_PROJECT,    /* built from a different project */
    FW_OTA_SWITCH_FAILED,    /* could not set the boot partition */
} fw_ota_result_t;

/*
 * Pick the inactive slot and start an update of `len` bytes. On success writes
 * the partition and handle to the out parameters.
 *
 * `len` is the real image size rather than OTA_SIZE_UNKNOWN, so only the
 * sectors the image needs are erased instead of the whole 4 MB slot.
 */
esp_err_t fw_ota_begin(size_t len, const esp_partition_t **part,
                       esp_ota_handle_t *handle);

/*
 * Finish an update: validate the image, confirm it is ours, and make it the
 * next boot partition. On success the caller is expected to reboot (see
 * fw_schedule_reboot) and `version_out` receives the new image's version.
 *
 * Checking project_name matters because esp_ota_end only proves the image is
 * well formed, not that it belongs here: without it, the bootloader or another
 * project's build is accepted now and only fails at the next boot.
 *
 * Do not call this until any checksum you intend to verify has passed - once
 * esp_ota_end has run, esp_ota_abort is no longer available.
 */
fw_ota_result_t fw_ota_finish(esp_ota_handle_t handle, const esp_partition_t *part,
                              char *version_out, size_t version_len);

void fw_ota_abort(esp_ota_handle_t handle);

/* Restart a couple of seconds from now.
 *
 * Deliberately deferred: a caller that answers an HTTP request must let the
 * response reach the client first, or the browser reports a network error and
 * the user cannot tell success from failure. */
void fw_schedule_reboot(void);

/* True for the errors esp_ota_write raises when the bytes are not an app image
 * at all. It validates the magic byte on the first chunk, so a wrong file is
 * caught immediately rather than after the whole upload. */
bool fw_ota_err_is_bad_image(esp_err_t err);

/* Short human-readable reason, for logs and for the panel. */
const char *fw_ota_result_text(fw_ota_result_t r);

/* ======================= automatic updates ======================= */

/*
 * One size for every error string this module produces or stores. They used to
 * differ, which is how a longer message turned into a -Werror build failure
 * about possible truncation the moment the message grew - and would otherwise
 * have become a silently clipped message in the panel.
 */
#define FW_ERR_MAX 192

typedef enum {
    FW_IDLE = 0,
    FW_CHECKING,       /* asking the server */
    FW_UP_TO_DATE,
    FW_AVAILABLE,      /* a newer release exists; waiting for the go-ahead */
    FW_DOWNLOADING,
    FW_INSTALLING,     /* written and verified, switching the boot partition */
    FW_ERROR,
} fw_state_t;

typedef struct {
    fw_state_t state;
    char running[32];      /* version compiled into this build */
    char latest[32];       /* version offered by the server ("" if unknown) */
    /* Sized to esp_partition_t.label (17) rather than to "ota_0"/"ota_1":
       snprintf is checked against the field's declared size, not the current
       value, so an 8-byte buffer fails the build as a potential truncation. */
    char slot[24];         /* partition this build is running from */
    uint32_t interval_hours;   /* 0 = periodic checks are off */
    bool auto_install;
    /* A release build can update itself; a development build cannot, and the
       panel disables the whole section rather than offering controls that do
       nothing. Decided when the artifact was built, not inferred at runtime. */
    bool release_build;
    /* The repository this build updates from, "owner/repo" ("" if unknown). */
    char build_repo[64];
    char url[256];
    char error[FW_ERR_MAX];
    int progress;          /* 0..100 while downloading, else 0 */
    int64_t last_check_us; /* 0 = never checked */
} fw_status_t;

/*
 * Load the settings and start the background task. Safe to call before the
 * network is up: the task waits to be told there is an IP.
 */
void fw_update_init(void);

/* Snapshot of the current state. Mutex-protected; safe from any task. */
void fw_update_status(fw_status_t *out);

/* Ask for a check (or an install) at the next opportunity. These return
 * immediately; the work happens on the update task. */
esp_err_t fw_update_check_now(void);
esp_err_t fw_update_install_now(void);

esp_err_t fw_update_set_interval(uint32_t hours);
esp_err_t fw_update_set_auto(bool on);
esp_err_t fw_update_set_url(const char *url);

/*
 * Tell the updater whether the station currently has an address.
 *
 * Callers are the WiFi event handlers. Inverting the dependency this way keeps
 * this module from reaching into the router's event group.
 */
void fw_update_set_online(bool online);

/* ======================= developer mode ======================= */

/*
 * A token that authorizes flashing without a panel session, for scripted or
 * automated updates.
 *
 * Off by default, and deliberately narrow: a valid token authorizes only the
 * firmware-update endpoints, not the panel as a whole, so a leaked token cannot
 * read the client list or change WiFi settings. It is the most powerful
 * credential on the device for the little it can do either way, which is why
 * enabling it is a separate, explicit switch rather than something that comes
 * on with the web panel.
 *
 * Presented in an X-OTA-Token header rather than a query parameter: URLs end up
 * in logs and referrers, headers do not.
 *
 * Over plain HTTP, like the panel password, so it is readable by anyone who can
 * observe the LAN. That is the same exposure the session cookie already has.
 */

/* Token length: 32 random bytes rendered as hex, plus the terminator. */
#define FW_DEV_TOKEN_LEN 65

bool fw_dev_mode(void);
esp_err_t fw_set_dev_mode(bool on);

/* Current token, or "" when none has been generated. Never NULL. */
void fw_dev_token(char *out, size_t out_len);

/* Replace the token with a fresh random one. */
esp_err_t fw_dev_token_regen(void);

/*
 * True when `presented` matches the current token and developer mode is on.
 * Compared without an early exit, so a wrong guess cannot be narrowed down by
 * how long the comparison took.
 */
bool fw_dev_token_ok(const char *presented);
