#!/usr/bin/env python3
"""Serve a firmware release feed from this machine, for testing.

Development should not wait on CI. This stands in for GitHub's releases API so
the whole update path - metadata, checksum, download, verify, flash - can be
exercised in seconds against a build sitting in build/.

It is not only a convenience. The GitHub release CDN is unreachable from some
networks (see CLAUDE.md), so a local feed is the only way to test an unattended
install there at all.

The URL carries the repository path so it mirrors a real feed:

    http://<host>:<port>/landsspacesss/embedwrt/releases/latest

Nothing requires that any more - the runtime repository check is gone - but a URL
shaped like the one you ship with is one less difference to explain.

The build has to be a release build (`idf.py -DEMBEDWRT_RELEASE=ON build`), and
`--version` has to be higher than what the device runs: a development build has
no update path at all, and the version comparison is strict.

    python3 tools/local_feed.py --version 1.5.1
    python3 tools/local_feed.py --version 1.5.1 --image build/embedwrt.bin
"""
import argparse
import hashlib
import http.server
import json
import os
import socket
import socketserver
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Mirrors the repository this project is built from, so the feed URL looks like
# the one the firmware would use in the field. Override with --repo if you forked.
DEFAULT_REPO = "landsspacesss/embedwrt"


class FeedHandler(http.server.BaseHTTPRequestHandler):
    version = "0.0.0"
    repo = DEFAULT_REPO
    assets = {}          # name -> (path, size, sha256)

    def log_message(self, fmt, *a):
        sys.stderr.write("  %s\n" % (fmt % a))

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = [p for p in self.path.split("/") if p]
        # Expected: <owner>/<repo>/releases/latest
        want_rel = self.repo.split("/") + ["releases", "latest"]
        if parts == want_rel:
            base = "http://%s:%d/%s/releases/download/v%s" % (
                self.server.bind_host, self.server.server_address[1],
                self.repo, self.version)
            assets = []
            for name, (path, size, digest) in sorted(self.assets.items()):
                assets.append({
                    "name": name,
                    "size": size,
                    "browser_download_url": "%s/%s" % (base, name),
                    # No "url" field: the firmware only prefers that for
                    # api.github.com, and a plain browser_download_url is what a
                    # self-hosted feed should look like.
                })
            self._json({
                "tag_name": "v%s" % self.version,
                "name": "v%s" % self.version,
                "draft": False,
                "prerelease": False,
                "body": "Local test feed",
                "assets": assets,
            })
            return

        # Expected: <owner>/<repo>/releases/download/<tag>/<asset> - six
        # segments, because the tag sits between "download" and the filename.
        if (len(parts) == 6 and parts[:2] == self.repo.split("/")
                and parts[2] == "releases" and parts[3] == "download"):
            name = parts[5]
            if name not in self.assets:
                self._json({"message": "Not Found"}, 404)
                return
            path, _, _ = self.assets[name]
            data = open(path, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self._json({"message": "Not Found", "path": self.path}, 404)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="version to advertise, e.g. 1.4.7")
    ap.add_argument("--image", default=os.path.join(ROOT, "build", "embedwrt.bin"))
    ap.add_argument("--full", default=os.path.join(ROOT, "build", "embedwrt-full-16MB.bin"),
                    help="merged image; skipped when absent")
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()

    if not os.path.exists(args.image):
        sys.exit("FATAL: %s not found - build first" % args.image)

    # The two assets the firmware actually uses. The checksum has to be served
    # under exactly the name it looks for, or the update is refused.
    FeedHandler.assets = {}
    FeedHandler.assets["embedwrt.bin"] = (args.image, os.path.getsize(args.image),
                                          sha256(args.image))

    # Written to disk rather than generated per request: it is then served by
    # the same code path as every other asset, so what the firmware fetches is
    # what was actually computed here.
    sha_path = os.path.join(ROOT, "build", "embedwrt.bin.sha256")
    with open(sha_path, "w") as f:
        f.write("%s  embedwrt.bin\n" % sha256(args.image))
    FeedHandler.assets["embedwrt.bin.sha256"] = (sha_path, os.path.getsize(sha_path),
                                                 sha256(sha_path))

    if os.path.exists(args.full):
        FeedHandler.assets["embedwrt-full-16MB.bin"] = (
            args.full, os.path.getsize(args.full), sha256(args.full))

    FeedHandler.version = args.version
    FeedHandler.repo = args.repo

    # The address a client would reach this machine on. gethostname() resolves
    # to the loopback alias here (127.0.1.1), which the device cannot use.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))          # TEST-NET-1; nothing is sent
        host = probe.getsockname()[0]
    except OSError:
        host = socket.gethostbyname(socket.gethostname())
    finally:
        probe.close()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", args.port), FeedHandler) as httpd:
        httpd.bind_host = host
        url = "http://%s:%d/%s/releases/latest" % (host, args.port, args.repo)
        print("serving v%s" % args.version)
        for name, (path, size, _) in sorted(FeedHandler.assets.items()):
            print("  %-28s %9d bytes" % (name, size))
        print()
        print("  set the panel's release feed to:")
        print("    %s" % url)
        print()
        print("  (release build required; --version must exceed the running one)")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
