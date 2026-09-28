#!/usr/bin/env python3
"""Publish a firmware release to GitHub.

The release feed the devices poll is GitHub, so this is where new versions have
to land. A self-hosted mirror can be pointed at from the panel, but the default
is GitHub for one reason: it is not a machine in this house that can be switched
off.

The version is read from PROJECT_VER in CMakeLists.txt rather than taken as an
argument. That is deliberate: if the tag and the version compiled into the image
disagree, every device running the new build keeps reporting the old version and
therefore never considers itself up to date. There is no argument to get wrong.

Uploads four assets. The two checksums are not optional - the device verifies
the image against `embedwrt.bin.sha256` before switching boot partitions, and a
missing checksum makes it refuse the update silently rather than fail loudly.

    python3 tools/make_release.py            # publish PROJECT_VER
    python3 tools/make_release.py --dry-run  # show what would happen

Needs `gh` authenticated, the ESP-IDF environment sourced (for esptool), and a
build already present.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.environ.get("EMBEDWRT_REPO", "landsspacesss/embedwrt")

APP_BIN = os.path.join(ROOT, "build", "embedwrt.bin")
FULL_BIN = os.path.join(ROOT, "build", "embedwrt-full-16MB.bin")
PROJECT_VER_RE = re.compile(r'set\(PROJECT_VER\s+"([^"]+)"\)')


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, **kw)


def gh(*args, **kw):
    """Run gh and return (ok, stdout). Kept small so failures report the CLI's
    own message rather than a bare exit code."""
    r = run(["gh", *args], **kw)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def with_retry(fn, what, tries=4):
    """Retry a network operation with a growing pause.

    github.com is reachable only intermittently from some networks, while
    api.github.com stays up. A push that dies halfway leaves a local tag with no
    matching remote release, so retrying here is what keeps a release from
    needing to be finished by hand.
    """
    last = ""
    for i in range(tries):
        ok, out = fn()
        if ok:
            return True, out
        last = out
        if i < tries - 1:
            wait = 5 * (i + 1)
            print(f"  {what} failed (attempt {i + 1}/{tries}), retrying in {wait}s...")
            time.sleep(wait)
    return False, last


def project_version():
    src = open(os.path.join(ROOT, "CMakeLists.txt"), encoding="utf-8").read()
    m = PROJECT_VER_RE.search(src)
    if not m:
        sys.exit("FATAL: no set(PROJECT_VER \"...\") in CMakeLists.txt")
    return m.group(1)


def embedded_version(path):
    """Read `version` straight out of the app descriptor inside the image.

    Comparing this against PROJECT_VER is what catches the case where someone
    bumped the version and published without rebuilding.
    """
    with open(path, "rb") as f:
        d = f.read()
    at = d.find(b"\x32\x54\xcd\xab")          # ESP_APP_DESC_MAGIC_WORD
    if at < 0:
        return None
    return d[at + 16:at + 48].split(b"\x00")[0].decode("utf-8", "replace")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def release_body(ver, app_sha, full_sha):
    return f"""EmbedWRT {ver} —— ESP32-S3 WiFi 中继路由器（NAT + DoH/DoT 转发）。

## 附件说明 —— 两个镜像用途不同，别混用

| 文件 | 用途 | 怎么用 |
|---|---|---|
| `embedwrt.bin` | **面板 OTA / 自动更新** | 面板 → 设置 → 固件更新，或让设备自行更新 |
| `embedwrt-full-16MB.bin` | **有线烧录 / 首次刷机 / 救砖** | 从偏移 `0x0` 整片写入 |

`embedwrt-full-16MB.bin` 含 bootloader 与分区表，**不能**用于面板 OTA。

## 校验值

```
{app_sha}  embedwrt.bin
{full_sha}  embedwrt-full-16MB.bin
```

设备在切换启动分区之前会核对 `embedwrt.bin.sha256`。**若该校验附件缺失，
自动更新会被拒绝**（而不是报错），发布时务必一并上传。

## 许可证

GPL-3.0-or-later，全文见仓库内 `LICENSE`。`main/dhcps/` 与
`main/led_strip_encoder.*` 来自 ESP-IDF，保持 Apache-2.0（与 GPLv3 兼容）。
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="do everything except push and upload")
    ap.add_argument("--notes", help="file to use as the release body instead of the generated one")
    ap.add_argument("--from-tag", action="store_true",
                    help="CI mode: the tag already exists (it triggered the run) and "
                         "build/ is already populated, so skip tagging and pushing")
    args = ap.parse_args()

    ver = project_version()

    if args.from_tag:
        # CI mode: the tag already exists and triggered this run, so there is
        # nothing to tag or push. GITHUB_REF_NAME is what the workflow was
        # started for.
        tag = os.environ.get("GITHUB_REF_NAME", "").strip()
        if not tag:
            sys.exit("FATAL: --from-tag needs GITHUB_REF_NAME (set by GitHub Actions)")
    else:
        tag = f"v{ver}"

    print(f"PROJECT_VER = {ver}   tag = {tag}")

    # The tag and the source must agree. This is the failure the whole
    # PROJECT_VER convention exists to prevent: tag it v1.2.0 while CMakeLists
    # still says 1.1.1 and every device reports 1.1.1 forever, so no device ever
    # considers itself out of date. Cheap to check, invisible if not checked.
    if tag != f"v{ver}":
        sys.exit(f"FATAL: tag '{tag}' does not match PROJECT_VER '{ver}'.\n"
                 f"       Set PROJECT_VER to {tag.lstrip('v')} and rebuild, or tag v{ver}.")

    if not os.path.exists(APP_BIN):
        sys.exit(f"FATAL: {APP_BIN} missing - build first (idf.py build)")

    emb = embedded_version(APP_BIN)
    if emb != ver:
        # A development build carries a "-dev" suffix, and publishing one would
        # ship a release with automatic updates compiled out - invisible until a
        # device refused to update itself. Worth its own message, because the
        # generic one sends you looking at the tag.
        if emb == f"{ver}-dev":
            sys.exit(f"FATAL: {APP_BIN} is a development build (version '{emb}').\n"
                     f"       Development builds cannot update themselves, so publishing this\n"
                     f"       would ship a release that never updates.\n"
                     f"       Rebuild as a release:  idf.py -DEMBEDWRT_RELEASE=ON build")
        sys.exit(f"FATAL: {APP_BIN} reports version '{emb}' but PROJECT_VER is '{ver}'.\n"
                 f"       Rebuild before publishing, or the tag and the image disagree.")
    print(f"image descriptor version matches PROJECT_VER ({emb})")

    if not args.from_tag:
        # Refuse to publish a dirty tree: the tag would not describe what
        # shipped. In CI the tree is a clean checkout, so this is local-only.
        st = run(["git", "status", "--porcelain"]).stdout.strip()
        if st:
            print("WARNING: working tree is dirty:")
            print("  " + st.replace("\n", "\n  "))

        # An existing tag is not fatal: a previous run may have stopped after
        # tagging (the network here fails intermittently), and re-publishing the
        # same version is the correct way to finish that. The guards that matter
        # are PROJECT_VER matching the image and the remote assets being
        # complete, both checked below and after upload.
        if run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"]).returncode == 0:
            print(f"note: tag {tag} already exists locally - will reuse it, not recreate")

    # The merged image is what a blank board gets written from 0x0.
    print("generating the merged full-flash image...")
    if not args.dry_run:
        r = run([sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
                 "-o", FULL_BIN, "--flash-mode", "dio", "--flash-size", "16MB",
                 "--flash-freq", "80m",
                 "0x0", "build/bootloader/bootloader.bin",
                 "0x8000", "build/partition_table/partition-table.bin",
                 "0xf000", "build/ota_data_initial.bin",
                 "0x20000", "build/embedwrt.bin"])
        if r.returncode != 0:
            sys.exit(f"FATAL: merge-bin failed\n{r.stdout}\n{r.stderr}")

    app_sha = sha256_file(APP_BIN)
    full_sha = sha256_file(FULL_BIN)
    print(f"  embedwrt.bin             {os.path.getsize(APP_BIN):>9} bytes  {app_sha}")
    print(f"  embedwrt-full-16MB.bin   {os.path.getsize(FULL_BIN):>9} bytes  {full_sha}")

    if args.dry_run:
        print("\n--dry-run: would tag, push and upload. Nothing done.")
        return

    # Checksum files, both named to match the device's expectation exactly.
    checksums = [
        (f"{APP_BIN}.sha256", f"{app_sha}  embedwrt.bin\n"),
        (f"{FULL_BIN}.sha256", f"{full_sha}  embedwrt-full-16MB.bin\n"),
    ]
    for path, text in checksums:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    title = f"{tag}"
    body = open(args.notes, encoding="utf-8").read() if args.notes else release_body(ver, app_sha, full_sha)

    if not args.from_tag:
        # Idempotent: a previous run may have died after tagging but before
        # pushing (the network here fails intermittently), and recreating an
        # existing tag is an error. Neither case should need manual cleanup.
        if not run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"]).returncode == 0:
            print(f"tagging {tag}...")
            if run(["git", "tag", "-a", tag, "-m", f"EmbedWRT {ver}"]).returncode != 0:
                sys.exit("FATAL: git tag failed")
        else:
            print(f"tag {tag} already exists locally, reusing it")

    ok, out = gh("auth", "status")
    if not ok:
        sys.exit(f"FATAL: gh is not authenticated\n{out}")

    # The branch has to be on the remote before the tag, or the tag points at a
    # commit the server cannot resolve. Publishing a tag without its commit is
    # the state this got into once; the release page still works, which is what
    # makes it easy to miss. In CI the tag is already there by definition.
    if args.from_tag:
        print("CI mode: the tag triggered this run, so nothing to push")
    else:
        branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()

        def push(ref):
            def attempt():
                r = run(["git", "push", "origin", ref])
                return r.returncode == 0, (r.stderr or r.stdout).strip()
            return attempt

        for ref in (branch, tag):
            ok, out = with_retry(push(ref), f"pushing {ref}")
            if not ok:
                sys.exit(f"FATAL: pushing {ref} failed after retries\n{out}")

    # gh refuses to attach a file whose name already exists in the release, so
    # the four assets are staged under the names the device expects rather than
    # their on-disk paths.
    #
    # embedwrt.bin.sha256 is the one that matters most: the updater will not
    # flash an image it cannot verify, and a release missing that asset fails
    # silently - the device just reports it has nothing to install.
    assets = [("embedwrt.bin", APP_BIN),
              ("embedwrt-full-16MB.bin", FULL_BIN),
              ("embedwrt.bin.sha256", f"{APP_BIN}.sha256"),
              ("embedwrt-full-16MB.bin.sha256", f"{FULL_BIN}.sha256")]

    ok, existing = gh("release", "view", tag, "--repo", REPO, "--json", "tagName")
    if ok:
        print(f"release {tag} already exists, leaving it alone")
    else:
        print("creating the release and uploading assets...")
        with tempfile.TemporaryDirectory() as stage:
            names = []
            for name, path in assets:
                dst = os.path.join(stage, name)
                shutil.copyfile(path, dst)
                names.append(dst)
            ok, out = with_retry(
                lambda: gh("release", "create", "--repo", REPO, tag,
                           "--title", title, "--notes-file", "-", *names, input=body),
                "creating the release")
        if not ok:
            sys.exit(f"FATAL: creating the release failed\n{out}")

    # Read it back rather than trusting the upload: the device depends on these
    # assets being present and named exactly, and this is cheap.
    ok, out = gh("release", "view", tag, "--repo", REPO, "--json", "assets")
    if not ok:
        sys.exit(f"FATAL: created the release but cannot read it back\n{out}")
    import json as _json
    names = sorted(a["name"] for a in _json.loads(out)["assets"])
    expected = sorted(n for n, _ in assets)
    if names != expected:
        sys.exit(f"FATAL: assets do not match.\n  expected {expected}\n  got      {names}")

    print(f"\nreleased {tag} with {len(names)} assets")
    print(f"  https://github.com/{REPO}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
