#!/usr/bin/env python3
"""Static evidence audit for ESP32 firmware. Does NOT establish runtime equivalence."""
import hashlib
import json
import re
import struct
from pathlib import Path

REFERENCE = Path("Firmware/XW-Drone.ino.merged.bin")
BUILT_MERGED = Path("build/XW-Drone.ino.merged.bin")
BUILT_APP = Path("build/XW-Drone.ino.bin")
SRC = Path("src/XW-Drone")
APP_OFFSET = 0x10000

def sha(data):
    return hashlib.sha256(data).hexdigest()

def esp_app_image(image):
    """Return parsed segments, segment-end, and basic metadata for ESP image."""
    if len(image) < 24 or image[0] != 0xE9:
        raise ValueError("not an ESP32 app image (magic not E9)")
    count = image[1]
    if not (1 <= count <= 16):
        raise ValueError(f"invalid segment count: {count}")
    pos = 24
    segs = []
    for i in range(count):
        if pos + 8 > len(image):
            raise ValueError("truncated segment header")
        addr, n = struct.unpack_from("<II", image, pos)
        pos += 8
        if n > len(image) - pos:
            raise ValueError(f"truncated segment {i} (addr 0x{addr:x}, size {n})")
        segs.append({"index": i, "address": addr, "size": n, "data": image[pos:pos+n], "offset": pos})
        pos += n
    return {
        "image_header": image[:24].hex(),
        "segment_count": count,
        "entry_address": f"0x{struct.unpack_from('<I', image, 4)[0]:08x}",
        "segments_end": pos,
        "segments": segs,
    }

def app_desc(image):
    idx = image.find(struct.pack("<I", 0xABCD5432), 0, min(len(image), 65536))
    if idx == -1:
        return {"found": False}
    def field(offset, n):
        return image[idx+offset:idx+offset+n].split(b"\0", 1)[0].decode("utf-8", "replace")
    return {
        "found": True, "offset": idx,
        "secure_version": struct.unpack_from("<I", image, idx+4)[0],
        "version": field(16, 32),
        "project_name": field(48, 32),
        "build_time": field(80, 16),
        "build_date": field(96, 16),
        "idf_version": field(112, 32),
        "elf_sha256": image[idx+144:idx+176].hex(),
    }

def ascii_strings(data):
    # Printable ASCII strings are a modest proxy for embedded protocol/UI/diagnostic text.
    return set(x.decode("ascii", "ignore") for x in re.findall(rb"[\x20-\x7e]{7,}", data))

def candidate_chunks(image, n=64):
    # Count stable, non-padding aligned blocks, regardless of their position.
    for seg in image["segments"]:
        b = seg["data"]
        for i in range(0, len(b) - n + 1, n):
            v = b[i:i+n]
            if len(set(v)) >= 8:
                yield hashlib.sha256(v).digest()

def analyze():
    ref_full = REFERENCE.read_bytes()
    rebuilt_full = BUILT_MERGED.read_bytes()
    built_app_full = BUILT_APP.read_bytes()
    ref_app_region = ref_full[APP_OFFSET:]
    ref = esp_app_image(ref_app_region)
    built = esp_app_image(built_app_full)
    ref_data = ref_app_region[:ref["segments_end"]]
    built_data = built_app_full[:built["segments_end"]]

    print("=== IMAGE AND BUILD METADATA ===")
    print(f"Reference merged: size={len(ref_full)} sha256={sha(ref_full)}")
    print(f"Rebuilt merged  : size={len(rebuilt_full)} sha256={sha(rebuilt_full)} match={ref_full == rebuilt_full}")
    print(f"Rebuilt app     : size={len(built_app_full)} sha256={sha(built_app_full)}")
    for title, x, img in [("REFERENCE", ref, ref_data), ("REBUILT", built, built_data)]:
        print(f"{title} app: segments={x['segment_count']} entry={x['entry_address']} parsed_end={x['segments_end']}")
        print(f"{title} header: {x['image_header']}")
        print(f"{title} descriptor: {json.dumps(app_desc(img), ensure_ascii=False)}")
        for seg in x["segments"]:
            print(f"{title} segment[{seg['index']}] load=0x{seg['address']:08x} size={seg['size']} sha256={sha(seg['data'])}")

    print("=== IDENTICAL CODE/DATA BLOCKS ===")
    ref_chunks = set(candidate_chunks(ref))
    built_chunks = set(candidate_chunks(built))
    common_chunks = ref_chunks & built_chunks
    print(f"distinct_nonpadding_64B_blocks: reference={len(ref_chunks)}, rebuilt={len(built_chunks)}, shared={len(common_chunks)}")
    print(f"block_overlap_by_rebuilt={len(common_chunks)/len(built_chunks) if built_chunks else 0:.4%}")
    print(f"block_overlap_by_reference={len(common_chunks)/len(ref_chunks) if ref_chunks else 0:.4%}")

    print("=== EMBEDDED WEB CONTROLLER ===")
    header = (SRC / "web_rc_html.h").read_text(encoding="utf-8")
    html_match = re.search(r'R"rawliteral\((.*?)\)rawliteral"', header, re.S)
    html = html_match.group(1).encode("utf-8") if html_match else b""
    html_equal_in_binaries = bool(html) and html in ref_data and html in built_data
    print(json.dumps({
        "source_embedded_html_bytes": len(html),
        "exact_source_html_in_reference": bool(html) and html in ref_data,
        "exact_source_html_in_rebuilt": bool(html) and html in built_data,
        "same_html_from_source_in_both": html_equal_in_binaries,
    }))

    print("=== FEATURE FINGERPRINTS ===")
    features = {
        "web_remote_routes": ["/web_rc", "/web_rc/heartbeat", "/web_rc/status"],
        "web_console_routes": ["/console/cmd", "/console/enable", "/console/disable"],
        "flight_modes": ["ACRO", "STAB", "ALTHOLD"],
        "parameter_control": ["CTL_R_RATE_P", "CTL_P_RATE_P", "CTL_Y_RATE_P", "CTL_FLT_MODE_0", "MOT_THR_MIN", "MOT_THR_MAX"],
        "parameter_hardware": ["MOT_PIN_FL", "MOT_PIN_FR", "MOT_PIN_RL", "MOT_PIN_RR", "IMU_ROT_ROLL"],
        "parameter_wifi": ["WIFI_AP_SSID", "WIFI_AP_PASS"],
        "wifi_ap": ["XW_Drone_WiFi", "192.168.4.1:8080"],
        "safety_messages": ["倒置保护", "禁止解锁", "自动降落", "自动上锁"],
    }
    marks = {}
    for cat, vals in features.items():
        out = {}
        for val in vals:
            key = val.encode("utf-8")
            out[val] = {"in_reference": key in ref_data, "in_rebuilt": key in built_data}
        marks[cat] = out
        print(f"{cat}: {json.dumps(out, ensure_ascii=False)}")

    print("=== STRING OVERLAP ===")
    sr = ascii_strings(ref_data)
    sb = ascii_strings(built_data)
    shared = sr & sb
    def likely_project(s):
        return bool(re.search(r"XW_|WEB|Web RC|web_rc|console|MOT_|SF_|CTL_|IMU_|WIFI_|RC_|Calibrat|battery|voltage|arming|drone|航|电|fail|Safe", s, re.I))
    # Only likely project-relevant strings, not generic library messages.
    only_ref = sorted(filter(likely_project, sr - sb), key=lambda s: (-len(s), s))[:45]
    only_build = sorted(filter(likely_project, sb - sr), key=lambda s: (-len(s), s))[:45]
    print(f"ascii_strings length>=7: reference={len(sr)} rebuilt={len(sb)} shared={len(shared)}")
    print(f"string_recall_by_rebuilt={len(shared)/len(sb) if sb else 0:.4%}")
    print(f"string_recall_by_reference={len(shared)/len(sr) if sr else 0:.4%}")
    print(f"source_like_strings_only_in_reference={json.dumps(only_ref, ensure_ascii=False)}")
    print(f"source_like_strings_only_in_rebuilt={json.dumps(only_build, ensure_ascii=False)}")

    print("=== EXACT SEGMENT BYTE COMPARISON ===")
    per_seg = []
    for rs in ref["segments"]:
        candidates = [bs for bs in built["segments"] if rs["address"] == bs["address"]]
        if not candidates:
            per_seg.append({"load_address": f"0x{rs['address']:x}", "matching_load_address": False})
            continue
        bs = candidates[0]
        min_len = min(len(rs["data"]), len(bs["data"]))
        same = sum(a == b for a,b in zip(rs["data"][:min_len], bs["data"][:min_len]))
        per_seg.append({
            "load_address": f"0x{rs['address']:x}", "matching_load_address": True,
            "size_ref": len(rs["data"]), "size_rebuilt": len(bs["data"]),
            "identical_bytes_at_same_relative_offsets": same,
            "compared_bytes": min_len, "ratio": round(same / min_len, 5) if min_len else 1,
            "exact_match": rs["data"] == bs["data"],
        })
    for x in per_seg:
        print(json.dumps(x))

    result = {
        "reference_merged_sha256": sha(ref_full),
        "rebuilt_merged_sha256": sha(rebuilt_full),
        "full_merged_exact_match": ref_full == rebuilt_full,
        "descriptors": {"reference": app_desc(ref_data), "rebuilt": app_desc(built_data)},
        "esp_image_segments_ref": ref["segment_count"],
        "esp_image_segments_built": built["segment_count"],
        "block_overlap_by_built": round(len(common_chunks) / len(built_chunks), 5) if built_chunks else None,
        "block_overlap_by_reference": round(len(common_chunks) / len(ref_chunks), 5) if ref_chunks else None,
        "exact_source_html_in_reference": bool(html) and html in ref_data,
        "exact_source_html_in_built": bool(html) and html in built_data,
        "feature_fingerprints": marks,
        "ascii_string_counts": {"reference": len(sr), "rebuilt": len(sb), "shared": len(shared)},
        "per_segment": per_seg,
        "interpretation": "STATIC_FINGERPRINTS_ONLY__DO_NOT_ASSERT_RUNTIME_EQUIVALENCE",
    }
    print("AUDIT_RESULT_JSON=" + json.dumps(result, ensure_ascii=False, separators=(",",":")))

if __name__ == "__main__":
    analyze()
