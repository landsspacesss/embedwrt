# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

EmbedWRT: an ESP32-S3 WiFi repeater. It joins an upstream network as a station,
re-broadcasts it on its own AP, and NATs between the two. Client DNS is answered
locally and forwarded over DoH or DoT, so lookups do not cross the upstream link
in plaintext. There is a web panel for configuration.

One binary, no OS. Target is an ESP32-S3 (Waveshare N16R8: 16 MB flash, 8 MB
PSRAM) on `/dev/ttyACM0`.

## Build, flash, run

`IDF_PATH` is not set in the shell, so source the export script first:

```sh
. /home/landspace/esp/esp-idf/export.sh   # ESP-IDF v6.1.0
idf.py build
idf.py -p /dev/ttyACM0 flash
idf.py -p /dev/ttyACM0 monitor            # WARNING: this resets the chip
```

**There is no test suite.** `idf.py test` does not apply here. Verification means
building, flashing, and then exercising the running device over HTTP — the panel
exposes JSON endpoints for every subsystem (`/api/clients`, `/api/leases`,
`/api/dnsrules`, `/api/portmaps`, `/api/acl`, `/api/apcfg`, `/api/dnstest`,
`/api/session`, `/api/version`, …). `/api/dnstest` is the one to reach for when a
resolver appears broken: it runs a real query through each configured resolver
using the same code the relay serves clients with.

The device is reachable three ways, which is convenient for testing:
`http://192.168.0.110/` from the upstream LAN, `http://192.168.4.1/` from a client
on its own AP, and `http://espwifi.local/` via mDNS. The upstream address comes
from DHCP and *changes*; find it by MAC `a4:cb:8f:c6:7b:ac` rather than assuming.

`sdkconfig` is **gitignored**; `sdkconfig.defaults` is the source of truth. After
editing it, delete `sdkconfig` and rebuild, otherwise the regenerated config keeps
the old values.

### Updating over the network

Once the OTA partition table is in place, `idf.py flash` is only needed for the
first install. After that there are two routes into the same code:

- **Settings → Firmware update** uploads `build/embedwrt.bin` by hand.
- **The same panel section can check a release feed and install what it finds**,
  either on a schedule or on a button. See "Automatic updates" below.

Both go through the primitives in `fw_update.c`. **The payload is
`build/embedwrt.bin`, the app image — not the merged full-flash image**, which
contains the bootloader and cannot go into an app slot. Two separate checks keep
that from being a footgun: the handler refuses any image whose `project_name` is
not `embedwrt`, and the updater only ever picks the release asset named exactly
`embedwrt.bin`.

Two consequences worth knowing before you change the partition table:

- **A partition-table change needs one wired flash.** The app moves, and the
  bootloader will not find it otherwise.
- **Keep `nvs` at `0x9000`/`0x6000`.** That offset is what makes the wired flash
  preserve the panel password, leases, DNS rules, port forwards, ACL and device
  records; NVS is not erased by `idf.py flash`. Moving it silently wipes the lot.

### Releasing

```sh
python3 tools/make_release.py --dry-run   # what would happen
python3 tools/make_release.py             # tag, push, publish, upload
```

It reads the version from `PROJECT_VER` in `CMakeLists.txt` and refuses to
publish if the image's embedded descriptor disagrees, so **bump `PROJECT_VER`
before releasing**. The reason is not tidiness: the device compares its own
compiled-in version against the release tag, so a tag that disagrees with the
image means the device reports the old version forever and considers itself
always up to date.

Four assets go up: both images and a `.sha256` for each. **The checksum assets
are required** — the updater refuses a release without `embedwrt.bin.sha256`,
because it will not flash an image it cannot verify. A release missing that
asset is not an error anyone sees until an update is attempted, which is why the
script uploads it every time rather than leaving it to memory.

### Automatic updates

`fw_update.c` holds both the OTA primitives and a background task that asks a
Gitea release feed whether something newer exists. Settings live in NVS under
`ota_url` (the `releases/latest` endpoint), `otachk` (hours; 0 = off) and
`otaauto` (install without asking). Endpoints, all admin-only: `/api/update`
(state), `/ota/check`, `/ota/install`, `/setotacfg`.

Design points that are deliberate:

- **Version comparison is strict.** Only a greater version counts, so the running
  build is never an update of itself and auto-install cannot loop.
- **Auto-install defaults off.** A restart drops every client, so the device
  announces and waits unless told otherwise.
- **The checksum is verified before `esp_ota_end`**, and a mismatch aborts the
  slot without touching the boot partition. Once `esp_ota_end` has run there is
  no abort left, which is why the order matters.
- The task blocks until the station has an address; the router tells it via
  `fw_update_set_online()` rather than the updater reaching into the router's
  event group.

**Hashing uses the PSA API, not `mbedtls_sha256_*`.** There is no
`mbedtls/sha256.h` in IDF 6.1 — it moved into the tf-psa-crypto private tree
behind `MBEDTLS_ALLOW_PRIVATE_ACCESS`, so the familiar calls do not compile. Use
`psa_hash_setup`/`psa_hash_update`/`psa_hash_finish` with `PSA_ALG_SHA_256`
(`psa/crypto.h`); the symbols are in libmbedcrypto already and go through the
chip's SHA acceleration.

**A reply with no `content-length` reads as length 0, not as empty.**
Gitea answers release metadata with `Transfer-Encoding: chunked`, and
`esp_http_client_fetch_headers()` returns 0 for that. Treating 0 as a real
length made every check fail with "short read (5862 of 0 bytes)". With the
length unknown the reply can also overflow the buffer, and truncating is the
worse failure: `tag_name` sits *after* the release notes in that JSON, so a
trimmed document parses cleanly and merely looks like no update is available.
The reader now errors explicitly instead — `esp_http_client_is_complete_data_received()`
is what distinguishes a complete reply from a full buffer.

**Security boundary.** The image is verified against a sha256 fetched over the
same plain-HTTP LAN connection, which catches truncation, flash corruption and
the wrong file — but **not** an attacker who can rewrite both the image and its
checksum. Resisting that needs a signature with the public key compiled in
(Ed25519; verification is milliseconds, unlike the ~2 s TLS handshake this chip
cannot afford). That is not implemented. In other words the device fetches and
executes code over an unauthenticated channel by design, so treat the Gitea host
as trusted. `ota_url` is settable from the panel, but only `http://` URLs are
accepted and only an admin can set it.

### Partitions, and why there is no factory slot

`partitions.csv` is `nvs` / `otadata` / `phy_init` / `ota_0` / `ota_1`, two 4 MB
app slots and no factory. With a blank otadata and no factory the bootloader
falls back to the first OTA slot and writes otadata itself, so the first wired
flash after a partition-table change boots `ota_0` with no extra step — that is
`bootloader_utility_load_boot_image` walking forwards from `start_index + 1`.

`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` is on, and it is the only mechanism
that recovers a build which is a *valid image* but dies at boot. An OTA'd image
starts as `PENDING_VERIFY`; if the device resets before
`esp_ota_mark_app_valid_cancel_rollback()` runs, the next boot marks it `ABORTED`
and boots the other slot. That call sits at the very end of `app_main()`, right
after `start_http_server()` and `start_mdns()` — late enough that "WiFi, DNS and
the panel all came up" is the test, early enough that the window in which a
restart could be mistaken for a failed boot is about two seconds. It returns an
error on a wired flash or an already-confirmed OTA, which is expected and
ignored.

**Do not add an early `esp_restart()` or `abort()` to `app_main` to test
something** — it will roll the device back. If you need a deliberate bad image
for a rollback test, build it, OTA it, and remove it; recovery from a device stuck
in a boot loop is a wired flash.

## The web page is generated — do not hand-edit it

`html_page` in `main/my_wifi_router.c` is ~1200 lines of escaped C string
literals (~75 KB of HTML). It is produced from `tools/gen_page.py`, which holds
the document naturally and emits the literals:

```sh
python3 tools/gen_page.py main/my_wifi_router.c
node --check main/page_as_served.js      # validate what the device will serve
```

`tools/gen_page.py` refuses to write if any of its checks fail. All four exist
because each one caught a real breakage:

- **Apostrophe inside a single-quoted JS string** (`this device's own...`)
  terminates the string and leaves the entire panel blank. Block comments are
  stripped before scanning, so prose in a `/* */` comment is not a false alarm.
- **A `//` comment truncates the whole script.** The page is one C string literal
  per line, so newlines are gone once compiled and a line comment swallows
  everything after it. The panel loads with no JavaScript and the tabs stop
  responding.
- **Validate as served, not as authored.** The generator writes the
  newline-stripped script to `main/page_as_served.js` (gitignored) precisely so
  `node --check` can inspect the real bytes. Checking the authored form passed
  while the served form was broken.
- **Every `data-i18n` / `t('...')` key must exist in both dictionaries.** The UI
  is bilingual (English/Chinese). Keys reached indirectly, e.g. as values of a
  lookup table like `DOH_STATE`, are exempted — verify those by hand. This check
  does **not** strip comments, unlike the apostrophe and line-comment checks, so
  a literal lookup call written into a comment as an example counts as a
  reference and fails the build with a key named after whatever you typed. Write
  prose around it instead. The same parsing exposes an easy way to break a
  translation: a value whose text ends in an ASCII colon, e.g. `'Installed:'`,
  looks like the start of the next `key:` pair and swallows the following entry;
  use a full-width colon or drop it.

**When editing the generator, splice by function boundary and watch the output
size.** A rewrite of one function once deleted ~20 KB of unrelated JavaScript,
because the end marker I chose occurred *earlier in the file* than the start
marker, so `s[:i] + new + s[j:]` silently removed everything between them instead
of replacing a function. The key check caught only a symptom (a missing
translation key). Recovery that worked: **restore the file from git and re-apply
the edits one at a time, checking a list of expected function names after each
step** — not patching the damaged copy. Two habits: pick the splice end as *the
next top-level `function` definition*, never a comment that could appear anywhere;
and sanity-check the output size — the generator prints the translated byte count
(`spliced: N bytes of HTML`) and `main/page_as_served.js` was ~62 KB when this was
written. A drop of tens of KB means something was deleted. Run the generator
before and after a change to compare, rather than trusting a remembered number.

## Where the pieces live

Most logic is in its own module; `my_wifi_router.c` is the largest file mainly
because it owns the HTML and the HTTP handlers.

| Module | Responsibility |
|---|---|
| `my_wifi_router.c` | Boot sequence, WiFi state machine, AP/STA config, every HTTP handler, the generated page |
| `dhcps/` | A vendored copy of ESP-IDF's DHCP server, extended for static leases |
| `ap_dhcp.c` | Starts that server and owns the rollback switch back to IDF's |
| `doh_relay.c` | UDP :53 listener, resolver selection, cache, per-resolver circuit breakers |
| `dot_client.c` | DNS-over-TLS: TLS stream plus the 2-byte length prefix |
| `dns_rules.c` | Per-device resolver policy (MAC → mode + address) |
| `static_leases.c` | MAC → fixed address |
| `devices.c` | IoT flag and owner per MAC, plus the two ownership policies |
| `portmap.c` | Port forwarding |
| `ap_acl.c` | AP client allow-list |
| `clients.c` | Associated-station table with AP-side RSSI, and IP → MAC |
| `web_auth.c` | Panel sessions, roles, and client-address resolution |
| `fw_update.c` | The OTA write sequence, shared by the upload handler and the automatic updater; plus the release-check task |
| `led_off.c` | Blanks the onboard WS2812 at boot (`led_strip_encoder.c` is IDF's, unmodified) |

### Request and packet flow

```
client ── AP ──┐
               ├── NAPT (lwIP IP forwarding) ── STA ── upstream router
upstream LAN ──┘
```

The AP sits on the station's channel, so a single radio never has to retune.
`esp_netif_set_default_netif(sta_netif)` matters: without it the device's own
DoH and SNTP traffic can leave via the AP.

Client DNS goes to `192.168.4.1` (advertised by the DHCP server, which must point
clients at *us* or they would bypass the relay). `doh_relay.c` answers and picks
a resolver per client MAC via `dns_rules.c`.

### Roles and device scoping

Two roles. **Admin** comes from a session cookie (`web_auth.c`); **guest** is
everything else. With no admin password set, every request is admin — the
behaviour from before roles existed, so a device that was never given a password
stays open rather than silently becoming guest-only.

A guest's identity is its **request's source address, mapped back to a MAC**
through `clients.c`, because an HTTP request carries nothing else. That single
fact drives the whole design:

- `caller_may_touch()` is the one authorization primitive in the request path:
  admins touch anything, a guest only what `devices.c` says it may - its own
  device, plus IoT devices it owns.
- **Listing is deliberately wider than editing.** `/api/clients` and `/api/devices`
  use `devices_listed_for_guest()`, which also includes *unowned* IoT devices so a
  guest can see one to claim it; the write guards still use `devices_visible()`.
  Rendering an edit form for a claimable-only device would just produce 403s.
- A caller from the upstream LAN has no MAC in the client table, so it owns
  nothing and sees nothing until it logs in. That is the correct outcome, not a
  gap - it has no device on this AP.

Two ownership policies live in `devices.c`, both on by default and both
admin-only to change: **guest_claim** lets a visitor take an *unowned* IoT device
(so one visitor cannot take a device another already manages) and hand it back;
**clear_on_visit** drops a device's IoT flag when that device *itself* loads the
panel, on the grounds that anything able to open a web UI is not a dumb IoT
device. The second only ever affects the requesting device's own record, which is
why it cannot lock anyone out.

### Storage

One NVS namespace, `"storage"`. Strings: `ssid`, `password` (upstream),
`ap_ssid`, `ap_pass`, `ap_hidden`, `ap_maxconn`, `ap_txpower`, `doh_url`,
`mdns_host`, `web_user`, `web_pass`, `ota_url`. Blobs: `leases`, `dnsrules`,
`pforwards`, `acl`, `devices`. Single bytes: `guestclaim`, `iotclrvis`,
`otaauto`. Numbers: `otachk` (u32, hours).

The hot-path tables (`static_leases`, `dns_rules`, `ap_acl`, `devices`) are
**double buffered**: readers follow an index and never take a lock, writers build
into the inactive copy and publish with a single store. They are read from the DNS
hot path and from the lwIP TCPIP thread, where blocking would stall forwarding for
every client.

Two habits worth keeping when adding a stored setting: **give the policy flags
their own keys rather than fields in a records blob**, because growing that struct
fails its size check on load and silently wipes every record; and **skip the NVS
write when nothing changes**, since `devices_clear_iot()` is called on *every*
request and committing each time would wear the flash for no reason.

## Gotchas that cost real time

**`idf.py monitor` resets the chip.** Right after a reset, associated clients
show an empty IP until their DHCP completes — which looks exactly like DHCP being
broken. Check the client's `uptime` before concluding anything: a small or reset
uptime means the chip restarted.

**Two DHCP servers cannot coexist.** The vendored copy and IDF's define the same
`dhcps_*` symbols, so `CONFIG_USE_OWN_DHCPS=y` requires `CONFIG_LWIP_DHCPS=n`.
Flipping both is the one-step rollback. `dhcps/upstream/` keeps a pristine copy
of IDF 6.1.0's file for diffing; `dhcps/README` records what was changed.

**`httpd_resp_set_hdr()` stores the pointer, it does not copy.** Passing a stack
buffer that goes out of scope before `httpd_resp_send()` makes the header be
written from reused stack — a `Set-Cookie` of binary garbage, identical on every
request. String literals are safe; a local buffer must be alive across the send.

**Sockets are a shared, scarce resource here.** `CONFIG_LWIP_MAX_SOCKETS` (raised
to 24 in `sdkconfig.defaults`) is global, and the web server alone asks for 7 via
`max_open_sockets` while the DNS relay, DoH TLS workers, DoT client, DHCP and SNTP
hold several more. At the IDF default of 10, a **fourth** concurrent HTTP
connection was refused, and a browser holding a few keep-alive sockets made the
panel unreachable entirely (ping fine, HTTP dead). Two consequences:

- Page loads run their requests **sequentially**, so the count stays at one
  however many panel sections exist. Adding a section means adding its loader to
  the chain: `loadSettings()` for anything in the Settings tab, and `fetchSeq()`
  in `loadClients()`/`loadGuestView()` elsewhere. A loader that fires its own
  parallel `fetch` is what breaks this.
- `lru_purge_enable` must stay **on**. Turning it off looks better (fail visibly
  rather than silently resetting the loser) but with no eviction idle keep-alive
  connections exhaust the pool permanently.

**`getpeername()` on an httpd request returns an IPv4-mapped IPv6 address.**
Family `AF_INET6`, `::ffff:a.b.c.d`, because the server socket is dual-stack.
Checking only for `AF_INET` rejects *every* request, which is subtle: guest
identity silently fails for all callers, and it looks like a permissions problem
rather than an address-parsing one. Accept both forms — `web_auth_client_ip()` is
the place. And when a lookup like this fails, **log the actual values** (`fd`,
family, length); guessing did not converge here, and one temporary log line named
it immediately. A bug that fails identically for a known-good caller is not
caller-specific: testing from the dev host, which is certainly not a client,
ruled out anything to do with the phone.

**Every route carries an explicit `admin_only` flag** and all of them go through
one trampoline, so a new endpoint cannot be added without a decision about who may
reach it. Most routes are admin-only; the guest-reachable ones are exactly `/`,
`/api/session`, `/login`, `/logout`, `/api/clients`, `/api/leases`,
`/api/dnsrules`, `/api/devices`, `/claim`, and the four device-scoped writes
(`/lease/add`, `/lease/del`, `/dnsrule/set`, `/dnsrule/del`). Those four are
deliberately *not* admin-only at the route level: they would otherwise return 401
before the per-device guard could decide, and a guest could never edit its own
device. They rely on `caller_may_touch()` instead, which fails closed.

**Answering a request whose body is still unread desynchronises the connection.**
The client sees the status line but not the body, so a rejection arrives as a
bare `500` with no explanation. This bit the OTA handler: `esp_ota_write()`
validates the image magic byte on the *first* chunk, so a non-firmware upload was
aborted with most of the body still unread, and the reason never reached the
browser. `ota_drain()` discards the remainder before responding. Any handler that
can fail part way through a large body needs the same treatment.

**Reaching the panel over the network from the dev host:** the panel password
lives in NVS, and there is no in-band recovery if it is forgotten. Clearing it
means erasing the NVS partition:

```sh
esptool.py -p /dev/ttyACM0 erase_region 0x9000 0x6000
```

**The panel is HTTP only.** `https://` will not connect; there is no TLS server.
Browsers that auto-upgrade to `https://` will fail, so the address must be typed
as `http://`.

## Hardware and network constraints worth knowing before proposing features

- **ESP32-S3 has no ECDSA/ECC hardware.** A full TLS handshake costs ~2 s of
  software big-integer arithmetic and that is irreducible. Session resumption is
  the effective lever, which is why `save_client_session` is set and why the
  relay reuses connections rather than reconnecting per query.
- **This network filters by destination.** Foreign DoH and DoT endpoints time out
  (TCP 443/853), while domestic ones work; foreign **plain DNS does work**. The
  preset lists in the panel reflect measurements, not assumptions — re-measure
  before adding a resolver to them.
- **iOS keeps one random MAC per remembered network.** Reconnecting to the same
  SSID preserves it; **changing the SSID or using "Forget This Network" produces a
  new one**, which silently invalidates static leases and per-device DNS rules.
- **One radio cannot associate with two APs**, and a client of this AP sits behind
  NAT — unreachable from the upstream LAN, so upstream devices cannot be used as
  test clients for forwarded traffic.

## Current state

`master` holds the working repeater plus every feature: static leases, port
forwarding, per-device DNS (DoH/DoT/plain), the client list, AP controls, mDNS,
sessions with an admin/guest role split, MAC-keyed IoT ownership with the two
claim policies above, and firmware update from the panel.

**Verified on hardware:** NAT forwarding (11.87 Mbps at close range, measured
server-side), DHCP including the awkward static-lease path, per-device DNS routing,
the client list with AP-side RSSI, mDNS resolution, the login/logout cycle, the
socket-pool and address-resolution fixes, and the guest view (its own device
listed, an unowned IoT device claimable, the claim written to NVS and surviving a
reboot).

**Verified on hardware, OTA:** a wired flash of the two-slot table booted `ota_0`
with no manual otadata step; every NVS-backed setting survived that reflash and
every OTA cycle since, byte-for-byte; uploads alternated `ota_0` / `ota_1`
with `/api/version` reporting the new slot; the bootloader rolled back to the
previous slot after an image that restarted before marking itself valid. Negative
cases all rejected without disturbing the running firmware: a text file, an
oversized body (over 4 MB), the bootloader, and a valid app image built from a
differently-named project.

**Verified on hardware, automatic updates:** the device found `v1.1.0` on its own
and installed it on request, then installed `v1.1.1` with **no click at all**
(only a check was triggered, and auto-install did the rest) — version, slot and
build time all confirmed afterwards. The scheduled check fired unattended about
two minutes after boot. A deliberately wrong `embedwrt.bin.sha256` was refused at
"checksum mismatch" with the device left running the old firmware and its config
untouched; a release missing the checksum asset, and one missing the app image
while still carrying the merged full-flash image, were both refused with a clear
reason. Settings survived the reboots that followed, and all four new endpoints
return 401 to a guest.

**Not verified:** the guest path for *editing* — a guest changing its own lease or
DNS, and releasing a device it holds — has been exercised over HTTP but not
through a browser on the AP since the guest view was reworked into collapsible
cards. Rollback has been proven on the manual upload path, not separately on the
automatic one; both call the same `fw_ota_finish`, so the mechanism is shared,
but the auto path has not itself been handed a bad image.

**Known limits of the update path:** a panel session lives in RAM, so an OTA
restart logs the administrator out; that is expected and the UI says so. The
image crosses the LAN in the clear on both routes, and its checksum does too, so
neither is a defence against someone who can rewrite both. Rollback covers a
build that crashes at boot, not one that boots but misbehaves — fix the latter by
uploading a good image, the panel is still up.
