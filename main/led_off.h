/* SPDX-License-Identifier: GPL-3.0-or-later */

#pragma once

/*
 * Switch off the onboard addressable RGB LED.
 *
 * A WS2812 latches whatever colour it was last sent, and this firmware never
 * drives it -- so after flashing it keeps showing the last frame written by
 * whatever ran before (the factory LED demo, typically). Nothing in software
 * clears it implicitly; we have to transmit an explicit black pixel.
 */
void led_off_silence_boot(void);
