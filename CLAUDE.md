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
`/api/session`, …). `/api/dnstest` is the one to reach for when a resolver
appears broken: it runs a real query through each configured resolver using the
same code the relay serves clients with.

The device is reachable three ways, which is convenient for testing:
`http://192.168.0.110/` from the upstream LAN, `http://192.168.4.1/` from a client
on its own AP, and `http://espwifi.local/` via mDNS. The upstream address comes
from DHCP and *changes*; find it by MAC `a4:cb:8f:c6:7b:ac` rather than assuming.

`sdkconfig` is **gitignored**; `sdkconfig.defaults` is the source of truth. After
editing it, delete `sdkconfig` and rebuild, otherwise the regenerated config keeps
the old values.

## The web page is generated — do not hand-edit it

`html_page` in `main/my_wifi_router.c` is ~2500 lines of escaped C string
literals. It is produced from `tools/gen_page.py`, which holds the document
naturally and emits the literals:

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
  lookup table like `DOH_STATE`, are exempted — verify those by hand.

## Where the pieces live

Most logic is in its own module; `my_wifi_router.c` is the largest file mainly
because it owns the HTML and the HTTP handlers.

| Module | Responsibility |
|---|---|
| `my_wifi_router.c` | Boot sequence, WiFi state machine, AP/STA config, every HTTP handler, the generated page |
| `dhcps/` | A vendored copy of ESP-IDF's DHCP server, extended for static leases |
| `doh_relay.c` | UDP :53 listener, resolver selection, cache, per-resolver circuit breakers |
| `dot_client.c` | DNS-over-TLS: TLS stream plus the 2-byte length prefix |
| `dns_rules.c` | Per-device resolver policy (MAC → mode + address) |
| `static_leases.c` | MAC → fixed address |
| `portmap.c` | Port forwarding |
| `ap_acl.c` | AP client allow-list |
| `clients.c` | Associated-station table with AP-side RSSI |
| `web_auth.c` | Panel sessions and roles |
| `led_off.c` | Blanks the onboard WS2812 at boot |

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

### Storage

One NVS namespace, `"storage"`. Strings: `ssid`, `password` (upstream),
`ap_ssid`, `ap_pass`, `ap_hidden`, `ap_maxconn`, `ap_txpower`, `doh_url`,
`mdns_host`, `web_user`, `web_pass`. Blobs: `leases`, `dnsrules`, `pforwards`,
`acl`.

The hot-path tables (`static_leases`, `dns_rules`, `ap_acl`) are **double
buffered**: readers follow an index and never take a lock, writers build into the
inactive copy and publish with a single store. They are read from the DNS hot
path and from the lwIP TCPIP thread, where blocking would stall forwarding for
every client.

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
  however many panel sections exist. Adding a section means adding it to that
  chain.
- `lru_purge_enable` must stay **on**. Turning it off looks better (fail visibly
  rather than silently resetting the loser) but with no eviction idle keep-alive
  connections exhaust the pool permanently.

**Every route carries an explicit `admin_only` flag** and all of them go through
one trampoline, so a new endpoint cannot be added without a decision about who
may reach it. `httpd_resp_set_hdr`-style oversights are not possible here because
the flag is positional in the route table.

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

`master` holds the working repeater plus every feature below. The panel currently
has two roles: an administrator (session cookie) and an unauthenticated guest. The
guest view exists and issues no admin requests, but **guest scoping is not
implemented yet** — a guest sees a notice rather than its own device. Next: let a
guest see and edit its own device and the devices it owns, via MAC-keyed IoT
ownership with administrator re-assignment.
