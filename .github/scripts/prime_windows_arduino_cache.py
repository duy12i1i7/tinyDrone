#!/usr/bin/env python3
"""Prime Arduino CLI's Windows archive cache from the official ESP32 index.

Official upstream package index is the trust anchor; no guessed archives or
unverified mirrors are used. Supports API-asset and direct-release transports.
Only ESP32 Dev Module build dependencies are selected, not RISC-V/debug/FS tools.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

INDEX_URL = "https://espressif.github.io/arduino-esp32/package_esp32_index.json"
TARGET_CORE = "3.3.1"
HOST = "x86_64-mingw32"
REQUIRED_TOOLS = {"esp32-arduino-libs", "esp-x32", "esptool_py"}
UA = "tinyDrone-firmware-audit/2026 GitHub-Actions"
LOCALAPPDATA = pathlib.Path(os.environ["LOCALAPPDATA"])
ARDUINO = LOCALAPPDATA / "Arduino15"
INDEX_PATH = ARDUINO / "package_esp32_index.json"
STAGING = ARDUINO / "staging" / "packages"
TOKEN = os.environ.get("GH_TOKEN", "")


def sha256_file(path):
    hash_ = hashlib.sha256()
    with open(path, "rb") as fh:
        while data := fh.read(1024 * 1024):
            hash_.update(data)
    return hash_.hexdigest()


def descriptor(asset):
    checksum = asset.get("checksum", "")
    if not checksum.startswith("SHA-256:"):
        raise ValueError(f"Expected SHA-256 for {asset.get('archiveFileName')}")
    return (asset["archiveFileName"], int(asset["size"]), checksum.split(":", 1)[1].lower(), asset["url"])


def verify(path, size, digest):
    return path.is_file() and path.stat().st_size == size and sha256_file(path) == digest


def github_asset_api(url):
    parsed = urllib.parse.urlparse(url)
    seg = urllib.parse.unquote(parsed.path).split("/")
    # /OWNER/REPO/releases/download/TAG/FILENAME
    if parsed.netloc != "github.com" or len(seg) < 7 or seg[3:5] != ["releases", "download"]:
        raise ValueError(f"Unexpected archive URL: {parsed.scheme}://{parsed.netloc}{parsed.path}")
    owner, repo, tag, filename = seg[1], seg[2], seg[5], "/".join(seg[6:])
    api = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    req = urllib.request.Request(api, headers={
        "User-Agent": UA, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
    })
    with urllib.request.urlopen(req, timeout=50) as response:
        tag_obj = json.load(response)
    matches = [a for a in tag_obj.get("assets", []) if a["name"] == filename and a.get("state") == "uploaded"]
    if len(matches) != 1:
        raise LookupError(f"No unique uploaded release asset {owner}/{repo} {tag} {filename}")
    x = matches[0]
    print(f"GitHub asset verified: {owner}/{repo}, {x['name']}, asset_id={x['id']}, size={x['size']}")
    return f"https://api.github.com/repos/{owner}/{repo}/releases/assets/{x['id']}"


def probe(url, description, headers):
    try:
        req = urllib.request.Request(url, headers=headers, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as response:
            host = urllib.parse.urlparse(response.url).hostname
            print(f"HEAD {description}: HTTP {response.status}, final_host={host}, content_length={response.headers.get('Content-Length')}")
    except Exception as e:
        print(f"HEAD {description}: {type(e).__name__} {str(e)[:150]}")


def try_download(url, out, size, digest, *, method):
    headers = {
        "User-Agent": UA,
        "Accept": "application/octet-stream" if method == "API" else "application/octet-stream",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if method == "API" and TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    request = urllib.request.Request(url, headers=headers)
    partial = out.with_name(out.name + ".partial")
    if partial.exists():
        partial.unlink()
    try:
        h = hashlib.sha256()
        total = 0
        with urllib.request.urlopen(request, timeout=150) as response:
            print(f"GET {method}: HTTP {response.status}, asset_host={urllib.parse.urlparse(response.url).hostname}, type={response.headers.get('Content-Type')}")
            if response.headers.get("Content-Type", "").startswith("application/json"):
                raise ValueError(f"GitHub returned JSON instead of binary for {method}")
            with partial.open("wb") as file:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    h.update(block)
                    file.write(block)
                    if total and total % (64 * 1024 * 1024) < len(block):
                        print(f"  {method}: {total // (1024 * 1024)} MiB verified in transit")
                    if total > size:
                        raise ValueError(f"Response larger than expected: {total} > {size}")
        actual = h.hexdigest()
        if total != size or actual != digest:
            raise ValueError(f"Size/hash mismatch: actual bytes={total} sha256={actual}; expected bytes={size} sha256={digest}")
        partial.replace(out)
        print(f"SHA256 VERIFIED: {out.name}, bytes={size}, sha256={actual}")
        return True
    except Exception as e:
        print(f"GET {method} failed: {type(e).__name__}: {str(e)[:250]}")
        return False
    finally:
        if partial.exists():
            partial.unlink()


def main():
    if not INDEX_PATH.exists():
        raise RuntimeError(f"Arduino index was not downloaded: {INDEX_PATH}")
    root = json.loads(INDEX_PATH.read_text(encoding="utf-8-sig"))
    vendors = [x for x in root["packages"] if x["name"] == "esp32"]
    if len(vendors) != 1:
        raise RuntimeError("Espressif package missing")
    pkg = vendors[0]
    platforms = [x for x in pkg["platforms"] if x["version"] == TARGET_CORE]
    if len(platforms) != 1:
        raise RuntimeError("ESP32 core 3.3.1 manifest missing")
    platform = platforms[0]
    deps = platform["toolsDependencies"]
    names = {x["name"] for x in deps}
    if not REQUIRED_TOOLS <= names:
        raise RuntimeError(f"Required tools missing from official manifest: {REQUIRED_TOOLS - names}")

    archives = [platform]
    for dep in deps:
        if dep["name"] not in REQUIRED_TOOLS:
            continue
        matches = [tool for tool in pkg["tools"] if tool["name"] == dep["name"] and tool["version"] == dep["version"]]
        if len(matches) != 1:
            raise RuntimeError(f"Missing tool: {dep}")
        systems = [s for s in matches[0]["systems"] if s["host"] == HOST]
        if len(systems) != 1:
            raise RuntimeError(f"No Windows host archive for {dep}: {[s['host'] for s in matches[0]['systems']]}")
        archives.append(systems[0])

    # This is diagnostic only; prevent CLI from requiring optional tools for
    # platforms not being compiled (ESP32-S3/C3, debugging, SPIFFS, etc.).
    omitted = {dep["name"] for dep in deps if dep["name"] not in REQUIRED_TOOLS}
    print(f"ESP32 3.3.1 optional tools skipped: {sorted(omitted)}")
    platform["toolsDependencies"] = [d for d in deps if d["name"] in REQUIRED_TOOLS]
    INDEX_PATH.write_text(json.dumps(root, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    STAGING.mkdir(parents=True, exist_ok=True)
    print(f"Staging archive directory: {STAGING}")
    failures = []
    for a in archives:
        name, size, digest, url = descriptor(a)
        target = STAGING / name
        print(f"=== {name} expected_size={size} sha256={digest} ===", flush=True)
        if verify(target, size, digest):
            print(f"CACHE HIT: {name} (SHA256 verified)")
            continue
        if target.exists():
            print(f"Removing invalid archive cache entry: {name}")
            target.unlink()

        try:
            api = github_asset_api(url)
        except Exception as e:
            print(f"GitHub API asset lookup failed: {type(e).__name__}: {str(e)[:180]}")
            api = None

        # HEAD probes are diagnostic; GET remains authoritative.
        direct_h = {"User-Agent": UA}
        probe(url, f"{name} direct", direct_h)
        if api:
            api_h = {"User-Agent": UA, "Accept": "application/octet-stream", **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})}
            probe(api, f"{name} authenticated API", api_h)

        # Try API first (GitHub authentication may bypass intermittent
        # unauthenticated release redirects), then original release URL.
        sources = ([("API", api)] if api else []) + [("DIRECT", url)]
        success = False
        for attempt in range(2):
            for method, uri in sources:
                if try_download(uri, target, size, digest, method=method):
                    success = True
                    break
            if success:
                break
            if attempt == 0:
                print("Retrying download after transient gateway error...", flush=True)
                time.sleep(8)
        if not success:
            failures.append(name)

    if failures:
        print(f"FAILED verified upstream downloads: {failures}")
        sys.exit(2)
    print("ALL REQUIRED ESP32 3.3.1 WINDOWS ARCHIVES VERIFIED AND CACHED")


if __name__ == "__main__":
    main()
