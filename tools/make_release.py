#!/usr/bin/env python3
"""Publish a firmware release to the private Gitea.

The version is read from PROJECT_VER in CMakeLists.txt rather than taken as an
argument. That is deliberate: if the tag and the version compiled into the image
disagree, every device running the new build keeps reporting the old version and
therefore never considers itself up to date. There is no argument to get wrong.

Uploads four assets. The two checksums are not optional - the device verifies
the image against `embedwrt.bin.sha256` before switching boot partitions, and a
missing checksum makes it refuse the update silently rather than fail loudly.

    python3 tools/make_release.py            # publish PROJECT_VER
    python3 tools/make_release.py --dry-run  # show what would happen

Needs the ESP-IDF environment sourced (for esptool) and a build already present.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.environ.get("GITEA_HOST", "http://192.168.0.105:3000")
OWNER = os.environ.get("GITEA_OWNER", "claude_code")
REPO_NAME = os.environ.get("GITEA_REPO", "embedwrt")

APP_BIN = os.path.join(ROOT, "build", "embedwrt.bin")
FULL_BIN = os.path.join(ROOT, "build", "embedwrt-full-16MB.bin")
PROJECT_VER_RE = re.compile(r'set\(PROJECT_VER\s+"([^"]+)"\)')


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, **kw)


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


def credentials():
    path = os.path.expanduser("~/.git-credentials")
    for line in open(path, encoding="utf-8").read().splitlines():
        if HOST.split("//")[-1].split(":")[0] in line:
            m = re.match(r"https?://([^:]+):([^@]+)@(.+)", line)
            if m:
                return m.group(1), m.group(2)
    sys.exit(f"FATAL: no credentials for {HOST} in ~/.git-credentials")


def api(method, path, data=None, ctype="application/json"):
    user, password = credentials()
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    body = json.dumps(data).encode() if (data is not None and ctype == "application/json") else data
    req = urllib.request.Request(HOST + path, data=body, method=method)
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


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
    r = run(["git", "push", "origin", tag])
    if r.returncode != 0:
        sys.exit(f"FATAL: pushing the tag failed\n{r.stderr}")

    print("creating the release...")
    status, resp = api("POST", f"/api/v1/repos/{OWNER}/{REPO_NAME}/releases",
                       {"tag_name": tag, "target_commitish": "master",
                        "name": title, "body": body, "draft": False, "prerelease": False})
    if status not in (200, 201):
        sys.exit(f"FATAL: creating the release failed ({status}): {resp}")
    rid = resp["id"]
    print(f"  release id {rid}")

    assets = [(APP_BIN, "embedwrt.bin"),
              (FULL_BIN, "embedwrt-full-16MB.bin"),
              (f"{APP_BIN}.sha256", "embedwrt.bin.sha256"),
              (f"{FULL_BIN}.sha256", "embedwrt-full-16MB.bin.sha256")]
    for path, name in assets:
        with open(path, "rb") as f:
            data = f.read()
        status, r = api("POST",
                        f"/api/v1/repos/{OWNER}/{REPO_NAME}/releases/{rid}/assets?name={name}",
                        data=data, ctype="application/octet-stream")
        if status not in (200, 201):
            sys.exit(f"FATAL: uploading {name} failed ({status}): {r}")
        print(f"  uploaded {name} ({len(data)} bytes)")

    print(f"\nreleased {tag}: {HOST}/{OWNER}/{REPO_NAME}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
