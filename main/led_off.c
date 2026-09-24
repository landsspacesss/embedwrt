/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "sdkconfig.h"
#include "driver/rmt_tx.h"

#include "led_strip_encoder.h"
#include "led_off.h"

#define LED_RMT_RESOLUTION_HZ  10000000
#define LED_RMT_MEM_SYMBOLS    64

static const char *TAG = "led_off";

/* WS2812 wants G, R, B in that order, MSB first. */
static esp_err_t write_pixel(int gpio, uint8_t r, uint8_t g, uint8_t b)
{
    rmt_channel_handle_t chan = NULL;
    rmt_encoder_handle_t encoder = NULL;
    bool enabled = false;
    esp_err_t err;

    rmt_tx_channel_config_t tx_cfg = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .gpio_num = gpio,
        .mem_block_symbols = LED_RMT_MEM_SYMBOLS,
        .resolution_hz = LED_RMT_RESOLUTION_HZ,
        .trans_queue_depth = 4,
    };
    err = rmt_new_tx_channel(&tx_cfg, &chan);
    if (err != ESP_OK) {
        return err;
    }

    led_strip_encoder_config_t enc_cfg = { .resolution = LED_RMT_RESOLUTION_HZ };
    err = rmt_new_led_strip_encoder(&enc_cfg, &encoder);
    if (err == ESP_OK) {
        err = rmt_enable(chan);
    }
    if (err == ESP_OK) {
        enabled = true;
        const uint8_t pixel[3] = { g, r, b };
        rmt_transmit_config_t tx_config = { .loop_count = 0 };
        err = rmt_transmit(chan, encoder, pixel, sizeof(pixel), &tx_config);
        if (err == ESP_OK) {
            /* Must finish before the channel and encoder are torn down. */
            rmt_tx_wait_all_done(chan, 100);
        }
    }

    if (enabled) {
        rmt_disable(chan);
    }
    if (encoder != NULL) {
        rmt_del_encoder(encoder);
    }
    rmt_del_channel(chan);
    return err;
}

void led_off_silence_boot(void)
{
    const char *list = CONFIG_LED_RGB_GPIO_LIST;
    if (list == NULL || list[0] == '\0') {
        return;
    }

    char buf[64];
    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

#if CONFIG_LED_RGB_TEST_COLORS
    int color_idx = 0;
#endif
    for (char *tok = strtok(buf, ", "); tok != NULL; tok = strtok(NULL, ", ")) {
        int gpio = atoi(tok);
        if (gpio < 0 || gpio > SOC_GPIO_PIN_COUNT - 1) {
            ESP_LOGW(TAG, "ignoring out-of-range GPIO %d", gpio);
            continue;
        }
        if (gpio >= 33 && gpio <= 37) {
            ESP_LOGW(TAG, "refusing GPIO %d: carries the octal PSRAM", gpio);
            continue;
        }
        uint8_t r = 0, g = 0, b = 0;
#if CONFIG_LED_RGB_TEST_COLORS
        /* Diagnostic mode paints a different primary colour per list position
         * so a glance at the board reveals which pin drives the LED. */
        static const uint8_t test_colors[][3] = {
            { 255, 0, 0 }, /* red */
            { 0, 255, 0 }, /* green */
            { 0, 0, 255 }, /* blue */
        };
        const uint8_t *c = test_colors[color_idx % 3];
        r = c[0];
        g = c[1];
        b = c[2];
        color_idx++;
#endif

        esp_err_t err = write_pixel(gpio, r, g, b);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "GPIO%d: %s", gpio, esp_err_to_name(err));
        } else {
#if CONFIG_LED_RGB_TEST_COLORS
            ESP_LOGI(TAG, "GPIO%d driven with a test colour", gpio);
#else
            ESP_LOGI(TAG, "GPIO%d driven black", gpio);
#endif
        }
    }
}
