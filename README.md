# EmbedWRT

**English** | [中文](README_zh.md)

An ESP32-S3 WiFi repeater. It joins an upstream network as a station,
re-broadcasts it on its own access point, and NATs between the two. Client DNS is
answered locally and forwarded over DNS-over-HTTPS or DNS-over-TLS, so lookups do
not cross the upstream link in plaintext. Everything is configured from a web
panel with an administrator/guest split, and the firmware updates itself over the
network.

One binary, no OS. The target is an ESP32-S3 with 16 MB flash and 8 MB PSRAM
(developed on a Waveshare ESP32-S3-DevKit N16R8).

> **Status:** working and in daily use, but a personal project rather than a
> polished product. The README describes what has actually been verified on
> hardware, and says so where something has not.

## What it does

- **Repeater with NAT** — AP+STA on one radio, so it never has to retune
- **Encrypted DNS relay** — DoH or DoT per device, chosen by MAC, with a cache
  and per-resolver circuit breakers. A device can also be pinned to plain DNS, or
  to a specific resolver, independently of everything else
- **Static leases** — MAC to fixed address, via a vendored copy of the IDF DHCP
  server
- **Port forwarding**, **AP client allow-list**, **hidden SSID**, TX power and
  client limits
- **Client list** with AP-side RSSI, hostname and join time
- **Guest mode** — a visitor without a login sees and edits only its own device,
  plus any IoT devices it owns
- **IoT ownership** — flag a device as IoT and assign an owner, so it can be
  managed by that owner without a panel login
- **mDNS** — reachable at `http://<hostname>.local/`
- **Firmware update from the panel**, and **automatic updates** from a GitHub
  release feed
- **Developer mode** — flash with an API token instead of a login, for scripting
- **Bilingual panel** (English / Chinese)

## Build and flash

Requires ESP-IDF **v6.1.0**.

```sh
. $IDF_PATH/export.sh
idf.py build
idf.py -p /dev/ttyACM0 flash monitor     # monitor resets the chip
```

The target is pinned to `esp32s3` in `sdkconfig.defaults`, so a fresh checkout
builds for the right chip without a separate `set-target`.

`sdkconfig` is not tracked. After editing `sdkconfig.defaults`, delete
`sdkconfig` and rebuild, or the regenerated config keeps the old values.

## Two images, and they are not interchangeable

A release carries both:

| File | Use it for | How |
|---|---|---|
| `embedwrt.bin` | **Panel update / automatic update** | Settings → Firmware update, or let the device update itself |
| `embedwrt-full-16MB.bin` | **Wired flash — first install, or recovery** | Written from offset `0x0`; bootloader and partition table included |

`embedwrt-full-16MB.bin` **cannot** be used for an over-the-air update — OTA
writes a single app slot, and the merged image contains a bootloader. Uploading
it to the panel is rejected (`not a valid firmware image`), but the error is
easier to avoid than to read.

## Updating over the network

Once the two-slot partition table is in place, `idf.py flash` is only needed for
the first install.

**A change to `partitions.csv` requires one more wired flash.** The app moves, and
the bootloader will not find it otherwise. Keep `nvs` at `0x9000`/`0x6000` — that
offset is what makes a reflash preserve the panel password, leases, DNS rules,
port forwards, ACL and device records. NVS is not erased by `idf.py flash`.

The device keeps two app slots and alternates between them. Boot-time rollback is
enabled: an image that is valid but crashes before finishing startup is reverted
by the bootloader, so a bad update does not leave a device that has to be
recovered over USB.

### Automatic updates

The panel checks a release feed on a schedule (off by default is an option;
default is daily) and can either announce a new version for confirmation or
install it unattended. Announce is the default, because a restart drops every
client and that is not a decision to make on someone's behalf.

The image is verified against the release's `embedwrt.bin.sha256` before the boot
partition is switched, and a release without that asset is refused rather than
installed unverified.

**Forking or editing this?** `DEFAULT_URL` in `main/fw_update.c` points at this
repository, so a device built from a fork would otherwise offer to replace its
own firmware with upstream's. That is refused rather than merely discouraged: the
build records which repository it came from, and a feed belonging to a different
one is rejected.

```
feed is 'landsspacesss/embedwrt', this firmware is not
```

To update from your own releases, set the feed URL in the panel to your
repository. A build with uncommitted changes is treated the same way — it will
not install updates automatically, because the point of an edit is that it should
not be silently overwritten. Manual upload and the developer-mode token still
work, since those are deliberate acts.

### Developer mode

For scripted or CI-driven updates, the firmware-update endpoints accept a token in
an `X-OTA-Token` header instead of an admin session:

```sh
curl -X POST --data-binary @embedwrt.bin \
  -H "Content-Type: application/octet-stream" \
  -H "X-OTA-Token: <token>" \
  http://192.168.4.1/ota
```

Off until switched on in the panel, which generates the token. It authorizes only
those three routes — a leaked token cannot read the client list or change WiFi
settings. It is sent in the clear over HTTP, like the panel password, so anything
that can watch the network can read it.

## Configuration

The panel is at `http://192.168.4.1/` from a client of its AP, at its DHCP
address on the upstream LAN, or at `http://<hostname>.local/`.

**The panel is HTTP only.** There is no TLS server, so typing `https://` will not
connect — and browsers that silently upgrade the scheme will fail.

There is no password until one is set, and **no in-band recovery if it is
forgotten**. Clearing it means erasing the NVS partition:

```sh
esptool.py -p /dev/ttyACM0 erase_region 0x9000 0x6000
```

## API

The panel is a static page that talks to JSON endpoints, so anything the UI does
can be scripted.

Most endpoints require an administrator session. The ones a client of the AP can
reach without logging in are the page itself, `/login`, `/logout`,
`/api/session`, `/claim`, the read-only `/api/clients`, `/api/leases`,
`/api/dnsrules` and `/api/devices`, and the four device-scoped writes
(`/lease/add`, `/lease/del`, `/dnsrule/set`, `/dnsrule/del`). Those four are not
admin-only at the route level on purpose: they would otherwise return 401 before
the per-device check could decide, and a guest could never edit its own device.
They are guarded by ownership instead, which fails closed.

Useful for diagnostics: `/status`, `/api/version` (installed version and
which slot it is running from), `/api/update` (auto-update state), and
`/api/dnstest`, which runs a real query through every configured resolver using
the same code path the relay serves clients with.

## Limitations

Worth knowing before you build one:

- **DoH protects the query, not the connection.** The TLS handshake that follows
  carries the hostname in cleartext (SNI), so a network operator can still see
  which sites you visit by name and address. What encryption hides is your DNS
  lookups; it is not a general-purpose privacy tool.
- **This is a NAT, not a tunnel.** Traffic from clients is forwarded, not
  encapsulated. The upstream router sees where clients actually go; it sees one
  IP address instead of several, which hides *who* rather than *what*.
- **There is no TLS server and no signature on updates.** The image is verified
  against a checksum fetched over the same connection, which catches truncation
  and corruption but not an attacker who can rewrite both. Treat the release feed
  as trusted.
- **A full TLS handshake costs about two seconds** on this chip — there is no
  ECC hardware, so it is software big-integer arithmetic. Session resumption is
  what keeps this usable, which is why the resolver reuses connections.
- **One radio cannot associate with two APs.** The repeater sits on the upstream
  channel, and clients of its AP are behind NAT, so they are not reachable from
  the upstream LAN.

## License

**GPL-3.0-or-later.** See `LICENSE`.

Derived from [ESP32 WiFi Pocket](https://github.com/Svarkovsky/esp32-wifi-pocket)
by Ivan Svarkovsky. Files under `main/dhcps/` and `main/led_strip_encoder.*` come
from ESP-IDF and remain Apache-2.0, which is compatible with GPLv3.
