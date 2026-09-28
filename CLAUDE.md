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
using the same code the relay serves clients with, and takes `?name=` to ask
about a particular hostname rather than the default `example.com`.

The device is reachable three ways, which is convenient for testing: from the
upstream LAN (whatever address DHCP handed it), `http://192.168.4.1/` from a
client on its own AP, and `http://espwifi.local/` via mDNS. The upstream address
*changes*; find it by the station MAC rather than assuming a fixed address. The
MAC is printed at boot (`wifi:mode : sta (...)`) and reported by `/status`.

`sdkconfig` is **gitignored**; `sdkconfig.defaults` is the source of truth. After
editing it, delete `sdkconfig` and rebuild, otherwise the regenerated config keeps
the old values.

**The target is pinned in `sdkconfig.defaults`, and has to be.** `sdkconfig` is
where `set-target` records the chip, and it is not checked in, so a fresh
checkout has no target and IDF silently defaults to `esp32`: the build succeeds
and produces an image for the wrong chip. A machine that ran `set-target` once
never notices, because `sdkconfig` remembers — which is exactly why this survives
until CI or a contributor hits it. `CONFIG_IDF_TARGET="esp32s3"` makes IDF guess
correctly from `sdkconfig.defaults` instead. Found by building the tagged tree in
an empty directory rather than trusting the local build.

### Updating over the network

Once the OTA partition table is in place, `idf.py flash` is only needed for the
first install. After that there are two routes into the same code:

- **Settings → Firmware update** uploads `build/embedwrt.bin` by hand.
- **The same panel section can check a release feed and install what it finds**,
  on a button always and on a schedule in release builds. See "Automatic updates"
  below, and note that a development build has no schedule.

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

### Developing: use a local feed, not CI

**Do not drive development through GitHub Actions.** A round trip is about three
minutes, and it only tells you what the build log says. Build locally and serve
the feed from this machine:

```sh
idf.py -DEMBEDWRT_RELEASE=ON build          # a release build: updates exist
python3 tools/local_feed.py --version 1.5.1 # prints the URL to use
```

Then set the panel's release feed to the printed URL. The whole path - metadata,
checksum, download, verify, flash, reboot - completes in about twenty seconds,
and the checksum fetch is exercised too, which is the step that cannot be
reached against GitHub from here.

**The build has to be a release build, or there is nothing to test.** A
development build has no update path, so pointing one at a local feed produces a
panel section that is hidden and endpoints that refuse. That is the design
working, but it is also the first thing that will look like a bug.

The feed URL happens to carry the repository path
(`.../<owner>/<repo>/releases/latest`) because it mirrors the real feed shape.
Nothing enforces that any more - the runtime repository check is gone - but a URL
that looks like the one you ship with is one less difference to explain.

Two more things that cost time here:

- **A panel session lives in RAM**, so it is gone after every reboot and any
  script that keeps a cookie starts seeing 401s. That reads as "the device did
  not come back", and did twice during this work. Log in again before concluding
  anything.
- **`--version` must be higher than the running build.** The comparison is
  strict, so a local feed advertising the same version the device already runs
  reports "up to date" and there is nothing to install.

CI is still how a *release* is built, because its value is a reproducible
artifact built from the tagged source on a machine that is not this one. It is
not the fast path, and should not be used as one.

### Releasing

**Tag it, and GitHub Actions does the rest.** `v*` triggers
`.github/workflows/release.yml`, which builds in the official ESP-IDF container
and uploads the four assets. The binaries on the release page are therefore built
by CI from exactly the tagged source, so they can be checked against it — and
publishing no longer depends on a machine in this house, which is the whole point
of hosting here.

```sh
# bump PROJECT_VER in CMakeLists.txt first, then:
git tag -a v1.3.1 -m "EmbedWRT 1.3.1" && git push origin v1.3.1
```

A local release still works when CI is not the right tool (or to reproduce a
failure): `python3 tools/make_release.py` builds, tags, pushes and uploads in one
step, and `--dry-run` shows what it would do. Both paths share the asset list,
the checksum naming and the verification, in `tools/make_release.py`; CI invokes
it with `--from-tag`, which skips tagging and pushing because the tag is what
started the run.

`make_release.py` reads the version from `PROJECT_VER` and refuses to publish if
the tag or the image's embedded descriptor disagrees, so **bump `PROJECT_VER`
before releasing**. The reason is not tidiness: the device compares its own
compiled-in version against the release tag, so a tag that disagrees with the
image means the device reports the old version forever and considers itself
always up to date. It also verifies the assets came back named correctly rather
than trusting the upload.

Four assets go up: both images and a `.sha256` for each. **The checksum assets
are required** — the updater refuses a release without `embedwrt.bin.sha256`,
because it will not flash an image it cannot verify. A release missing that
asset is not an error anyone sees until an update is attempted, which is why the
script uploads it every time rather than leaving it to memory.

Two things the workflow needs that are easy to miss:

- **`workflow` token scope.** Pushing a commit that touches
  `.github/workflows/` is rejected without it, on both the git and the REST
  path, with a message about the PAT. `gh auth refresh -s workflow` adds it.
- **`dependencies.lock` is tracked.** It pins the managed components
  (`espressif/mdns`, `cJSON`) so CI builds the same versions as a local build.
  Untracked, the runner resolves `^1.0.2` afresh and can pull a version nobody
  tested — a worse failure for a firmware release than a red build, because the
  image would differ from the verified one.

### Automatic updates

`fw_update.c` holds both the OTA primitives and a background task that asks a
release feed whether something newer exists. The default feed is the GitHub
`releases/latest` endpoint for `landsspacesss/embedwrt`; a self-hosted mirror can
be pointed at from the panel, which is what `ota_url` is for. Settings live in
NVS under `ota_url`, `otachk` (hours; 0 = off) and `otaauto` (install without
asking). Endpoints: `/api/update` (state), `/ota/check`, `/ota/install`,
`/setotacfg`.

Design points that are deliberate:

- **A build only updates from its own repository, and only a release build
  updates at all.** Both are properties of the build rather than run-time checks;
  the paragraphs below on the development/release split are where that lives, and
  they replaced the checks that used to enforce it.
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
- **Only the asset named exactly `embedwrt.bin` is used.** Releases also carry
  the merged full-flash image, and writing that into an app slot cannot work.
- **A release without `embedwrt.bin.sha256` is refused**, not installed
  unverified, so the checksum asset is not optional on the publishing side.

**Development and release are separate builds, and the split is what removed the
runtime guard.** A *release* build updates itself; a *development* build never
does anything on its own - no scheduled checks, no auto-install. Everything
manual still works in both: the panel section, checking, and installing. That is
deliberate, because developing the update path means pointing the device at a
test feed and pushing a build.

Four places enforce it, and the redundancy is intentional for the one that
matters: the scheduler never sets `will_check`, `load_settings` clears
`auto_install` (leaving the stored value alone), `fw_update_set_interval`
refuses a non-zero interval, and the auto-install call itself is guarded. That
last one replaces someone's firmware without being asked, so it should not
depend on one earlier assignment staying correct.

The earlier design shipped one binary and decided at run time whether its feed
could be trusted. That needed heuristics - which repository the build came from,
whether the tree was clean - and both were got wrong at least once, silently.
Here the answer is a property of how the artifact was produced:

```sh
idf.py build                            # development
idf.py -DEMBEDWRT_RELEASE=ON build      # release
```

The panel keeps the update section in a development build and disables the two
controls that describe automatic behaviour - the frequency selector and
auto-install - with a note saying why. Hiding the section was the first attempt
and was wrong: it made the update path untestable from a development build,
which is exactly when you need to test it.

`FW_DEFAULT_REPO` comes from `EMBEDWRT_REPO`, which CI sets from
`$GITHUB_REPOSITORY`. So a fork's release build points at the fork with nothing
to configure, and a device is never offered a firmware built from someone else's
repository - the property the runtime check used to provide, obtained by
construction instead.

A development build also carries `-dev` in its version. That is honest in the
panel, and it closes a footgun: `make_release.py` refuses to publish when the
image's embedded version disagrees with `PROJECT_VER`, so a local build cannot be
published as a release by accident. Without the suffix the check would pass and
the release would ship with updates compiled out - invisible until a device
refused to update itself.

Two things to know if you touch the definitions: `add_compile_definitions()` at
the top level does **not** reach an ESP-IDF component, and the failure is silent
(the macro stays undefined, the release build behaves like a development one);
they have to be attached in `main/CMakeLists.txt` with
`target_compile_definitions`. And a cache variable has to be read before
`project()`, because `PROJECT_VER` is consumed there. Verify by comparing the two images, not by
reading the build log: the versions differ (`1.5.0` against `1.5.0-dev`), and
`strings build/embedwrt.bin | grep 'development build: automatic updates are
off'` appears in a development build and not in a release one.

**The release CDN is unreachable from the device on this network, and that is
not a firmware problem.** `release-assets.githubusercontent.com` — where every
release asset actually lives, behind a 302 from both `api.github.com` and
`browser_download_url` — cannot be reached *by this device*, while the same URL
downloads fine from another machine on the same LAN over the same route. So the
check succeeds and the install cannot: `/api/update` reports `cannot connect to
release-assets.githubusercontent.com: ESP_FAIL`.

Ruled out, with the experiment that ruled it out, so nobody repeats them:

- **Certificate trust.** Building with `crt_bundle_attach` removed (verification
  off) failed identically, which is what shows this is transport and not trust.
- **Cross-signed chains.** The chain is cross-signed (leaf ← YR1 ← Root YR, and
  Root YR is cross-signed by ISRG Root X1), and IDF's bundle genuinely cannot
  verify that without `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY`.
  That option is now on, and it did **not** fix this.
- **DNS.** The resolver the device uses returns the same A records as one that
  works, and the addresses are the ones the working machine connects to.
- **Memory.** ~119 KB of internal heap free at the time of the failure.
- **The Accept header.** A real bug, since GitHub's asset endpoint answers JSON
  unless asked for `application/octet-stream` — but a separate one, fixed earlier.

The comparison that misleads: testing from the development host *looks* like the
same network, and is not. That host resolves through Tailscale MagicDNS, and
more importantly it is a different device as far as the router is concerned. A
router that filters per client or per destination will pass one and drop the
other, which makes "works here, fails there" read as a firmware fault.

What this means in practice: publishing works, the check works, and installing
automatically does not work from behind this network. Manual upload from the
panel and `POST /ota` with a developer token both still work, and are the paths
to use here.

**GitHub, not a server on the LAN.** The feed used to be a self-hosted Gitea and
was moved for a concrete reason: the device should not depend on a machine that
can be switched off. Two consequences of GitHub specifically:

- **The repo has to be public.** The device fetches anonymously, and GitHub
  answers 404 (not 403) for a private repo to an unauthenticated caller, so a
  private repo looks exactly like a missing one.
- **`browser_download_url` is not always reachable.** It points at github.com,
  which on some networks is blocked while `api.github.com` is not. The per-asset
  API `url` stays on api.github.com, so `asset_fetch_url()` prefers it when the
  host is api.github.com and only falls back to `browser_download_url` otherwise
  (a Gitea mirror's `url` means something different).

**Redirects are followed by hand, and have to be.** Automatic redirects only
exist inside `esp_http_client_perform()`, which buffers the whole body and is
therefore unusable for a 1.2 MB image; on the streaming path a 3xx arrives as-is
and would look like a server error. GitHub hands back a signed object-storage URL
per asset, so `fw_http_get_open()` loops on `Location`, captured via
`HTTP_EVENT_ON_HEADER` because there is no API to read a response header. A
signed URL measures 910-930 characters, hence `FW_URL_MAX` at 2048.

**Hashing uses the PSA API, not `mbedtls_sha256_*`.** There is no
`mbedtls/sha256.h` in IDF 6.1 — it moved into the tf-psa-crypto private tree
behind `MBEDTLS_ALLOW_PRIVATE_ACCESS`, so the familiar calls do not compile. Use
`psa_hash_setup`/`psa_hash_update`/`psa_hash_finish` with `PSA_ALG_SHA_256`
(`psa/crypto.h`); the symbols are in libmbedcrypto already and go through the
chip's SHA acceleration.

**A reply with no `content-length` reads as length 0, not as empty.** GitHub
answers release metadata with a chunked reply, and
`esp_http_client_fetch_headers()` returns 0 for that. Treating 0 as a real length made
every check fail with "short read (5862 of 0 bytes)". With the length unknown the
reply can also overflow the buffer, and truncating is the worse failure:
`tag_name` sits *after* the release notes in that JSON, so a trimmed document
parses cleanly and merely looks like no update is available. The reader errors
explicitly instead — `esp_http_client_is_complete_data_received()` is what
distinguishes a complete reply from a full buffer.

**The check buffer is 32 KB and the release JSON is ~9.6 KB.** Measured, not
guessed: a release with a long body and many assets can be far larger (a
40-asset release was 55 KB and tripped the limit), but that is what the explicit
error is for. It has to stay an error rather than a trim, and it cannot be sized
to the worst case because internal RAM is only ~72 KB free.

**Security boundary.** The image is verified against a sha256 fetched over the
same HTTPS connection, which catches truncation, flash corruption and the wrong
file — but **not** an attacker who can rewrite both the image and its checksum.
Resisting that needs a signature with the public key compiled in (Ed25519;
verification is milliseconds, unlike the ~2 s TLS handshake this chip cannot
afford). That is not implemented, so a compromised release feed means compromised
firmware. `ota_url` is settable from the panel, but only `http://` or `https://`
URLs are accepted and only an admin can set it.

### Developer mode: flashing with a token

`/ota`, `/ota/check` and `/ota/install` accept an `X-OTA-Token` header in place
of an admin session, so a script can install firmware without a browser. The
field is `token_ok` on `route_t` and nothing else sets it.

Deliberate limits, because a token that can replace firmware is the most powerful
credential on the device:

- **Off until switched on** (`/setdevmode`), and the token is generated on first
  enable rather than left empty.
- **Scope is three routes.** A leaked token cannot read the client list or change
  WiFi settings; every other admin-only route still 401s with a valid token.
- **`/api/devmode` is not itself token-authorized**, so a token cannot be read
  back or rotated with the token alone.
- **Compared without an early exit**, so a wrong guess leaks nothing through
  timing.
- **Header, not query string**: URLs end up in logs and referrers.
- Over HTTP in the clear, like the panel password. Anyone who can watch the LAN
  can read it, which is what the panel warning says.

Note that `route_t` gained a field, and `-Wextra` plus `-Werror` forced every
existing route to spell it out. That churn is the existing design working: a new
endpoint (or field) cannot be added without a decision about who may reach it.

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
`mdns_host`, `web_user`, `web_pass`, `ota_url`, `devtoken`. Blobs: `leases`,
`dnsrules`, `pforwards`, `acl`, `devices`. Single bytes: `guestclaim`,
`iotclrvis`, `otaauto`, `devmode`, `bw20` (channel width). Numbers: `otachk`
(u32, hours).

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

**A task that gains a TLS handshake needs a bigger stack than the one it had.**
The update task was created with 8192 because its feed was plain HTTP on the LAN,
and the comment beside it said exactly that. Pointing it at an HTTPS feed made
the comment false and nothing revisited the number, so every check overflowed:
the device rebooted a few seconds in, came back with its RAM sessions cleared,
and reported nothing at all. The DoH relay needs 10240 for the same handshake and
says so in its own comment; this path also keeps the redirect buffers on its
stack, so it is sized well past that (see `FW_TASK_STACK`).

The clue that places the fault is that it did **not** roll back. A crash in
`app_main` before `esp_ota_mark_app_valid_cancel_rollback()` triggers the
bootloader's revert; a crash in a task afterwards does not, so the device looks
like it merely hiccupped. When a device reboots for no apparent reason, check
whether a task is doing something its stack was not sized for.

**A local variable named `t` shadows the translation helper.** The panel's
translation function is `t()`, and a section that stored a DOM element in a local
`t` made every label in it throw at runtime. It generated cleanly and passed
`node --check`, because both only look at syntax. Fixing it needs the panel
actually opened; the generator's key check cannot see this class of bug.

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

`route_t` also carries `token_ok`, which lets the developer token stand in for a
session on that route. Exactly three routes set it (`/ota`, `/ota/check`,
`/ota/install`) and the compiler enforces the decision: `-Wextra` flags a missing
field initializer and this project builds with `-Werror`, so a new route has to
state its answer rather than inherit one. The route table is 49 entries against
`max_uri_handlers` of 60.

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
claim policies above, and firmware update from the panel. It builds as either a
development or a release build, and only the latter updates itself.

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
reason. Settings survived the reboots that followed, and the new endpoints return
401 to a guest.

**Verified on hardware, HTTPS feed and developer mode:** the device performs an
HTTPS check against `api.github.com` and reports a clean result — the run that
proved this also proved the stack fix, by staying reachable and keeping its
session for the whole check instead of rebooting. A real image was installed
three times using only `X-OTA-Token`, with the slot alternating each time. The
auth matrix was exercised: absent, wrong and wrong-length tokens all 401; the
correct token reaches the handler; six admin-only non-OTA routes still 401 with a
valid token; `/api/devmode` is unreadable anonymously. Rotating the token
invalidates the old one immediately, disabling developer mode invalidates a
valid one, and settings plus token survive a reboot. The panel section renders
correctly in both languages.

**Verified by building both channels:** a dev build reports `1.5.0-dev` and
carries the development-build message while a release build does not, and
`make_release.py` refuses to publish the dev one. Both link the update task,
since manual checking and installing work in either.

**Not yet verified on hardware:** the dev/release behaviour at run time - that a
dev build never checks on its own but still checks and installs by hand, that its
panel disables only the two automatic controls, and that a release build updates
from a configured feed. The artifacts are confirmed; the running device has not
been exercised since the change, because the board was unplugged.

**Verified on hardware, the install path itself:** pointed at the local feed
(`tools/local_feed.py`), the device completed the entire flow against a release
build — metadata, checksum fetch, download, verify, write, reboot — and came up
on the new version with the slot flipped. That includes the checksum fetch, the
step that cannot be reached against GitHub from here, and it is what establishes
that the firmware's half is sound and the GitHub failure is transport.

**Verified on hardware, unattended install — blocked by the network, not the
firmware:** the device reaches `api.github.com` and reports `up to date` against
the live public feed, and it installs correctly when the image is pushed to it
(panel upload, or `POST /ota` with a developer token). It cannot install itself
from the feed on this network, because the asset CDN is unreachable from it —
see the note above for the experiments that rule out the firmware.

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
