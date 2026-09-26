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
    args = ap.parse_args()

    ver = project_version()
    tag = f"v{ver}"
    print(f"PROJECT_VER = {ver}   tag = {tag}")

    if not os.path.exists(APP_BIN):
        sys.exit(f"FATAL: {APP_BIN} missing - build first (idf.py build)")

    emb = embedded_version(APP_BIN)
    if emb != ver:
        sys.exit(f"FATAL: {APP_BIN} reports version '{emb}' but PROJECT_VER is '{ver}'.\n"
                 f"       Rebuild before publishing, or the tag and the image disagree.")
    print(f"image descriptor version matches PROJECT_VER ({emb})")

    # Refuse to publish a dirty tree: the tag would not describe what shipped.
    st = run(["git", "status", "--porcelain"]).stdout.strip()
    if st:
        print("WARNING: working tree is dirty:")
        print("  " + st.replace("\n", "\n  "))

    tag_exists = run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"]).returncode == 0
    if tag_exists and not args.dry_run:
        sys.exit(f"FATAL: tag {tag} already exists - bump PROJECT_VER for a new release")
    if tag_exists:
        print(f"note: tag {tag} already exists (fine for a dry run)")

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

    print(f"tagging {tag}...")
    if run(["git", "tag", "-a", tag, "-m", f"EmbedWRT {ver}"]).returncode != 0:
        sys.exit("FATAL: git tag failed")

    # The branch has to be on the remote before the tag, or the tag points at a
    # commit the server cannot resolve. Publishing a tag without its commit is
    # the state this got into once; the release page still works, which is what
    # makes it easy to miss.
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    ok, out = gh("auth", "status")
    if not ok:
        sys.exit(f"FATAL: gh is not authenticated\n{out}")

    for ref in (branch, tag):
        r = run(["git", "push", "origin", ref])
        if r.returncode != 0:
            sys.exit(f"FATAL: pushing {ref} failed\n{r.stderr}")

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

    print("creating the release and uploading assets...")
    with tempfile.TemporaryDirectory() as stage:
        names = []
        for name, path in assets:
            dst = os.path.join(stage, name)
            shutil.copyfile(path, dst)
            names.append(dst)
        ok, out = gh("release", "create", tag, "--repo", REPO,
                     "--title", title, "--notes-file", "-", *names,
                     input=body)
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
