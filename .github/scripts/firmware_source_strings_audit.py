#!/usr/bin/env python3
"""Additional source-literal and relocation-tolerant evidence. Not a runtime proof."""
from pathlib import Path
from hashlib import blake2s
import json
import re
from firmware_static_audit import esp_app_image
SRC=Path("src/XW-Drone")
ref_full=Path("Firmware/XW-Drone.ino.merged.bin").read_bytes()
built_full=Path("build/XW-Drone.ino.bin").read_bytes()
ref=esp_app_image(ref_full[0x10000:])
built=esp_app_image(built_full)
ref_region=ref_full[0x10000:0x10000+ref["segments_end"]]
built_region=built_full[:built["segments_end"]]

def normalise_c_literal(s):
    # Handle ordinary literal escaping; keep UTF-8 Chinese intact.
    return s.replace(r'\"','"').replace(r'\r','\r').replace(r'\n','\n').replace(r'\t','\t').replace(r'\\','\\')

source_literals={}
for path in sorted(SRC.iterdir()):
    if path.suffix not in (".ino",".h") or path.name=="web_rc_html.h":
        continue
    s=path.read_text(encoding="utf-8")
    for m in re.finditer(r'"((?:\\.|[^"\\\n])*)"', s):
        v=normalise_c_literal(m.group(1))
        if len(v) < 6 or v.startswith("http://") or v.startswith("https://") or v.endswith((".h",".ino")):
            continue
        if v not in source_literals:
            source_literals[v]=[]
        source_literals[v].append(path.name)

retained={k:paths for k,paths in source_literals.items() if k.encode() in built_region}
both={k:paths for k,paths in retained.items() if k.encode() in ref_region}
missing={k:paths for k,paths in retained.items() if k.encode() not in ref_region}
print("=== SOURCE LITERAL PRESENCE ===")
print(f"unique_source_lits={len(source_literals)} built_embedded={len(retained)} shared_with_reference={len(both)} absent_in_reference={len(missing)}")
for k,files in sorted(missing.items(),key=lambda x:x[1][0])[:100]:
    print("SOURCE_LITERAL_MISSING_IN_REFERENCE=" + json.dumps({"files":files,"literal":k},ensure_ascii=False))
for cat,rex in {"safety":r"电量|倒置|解锁|上锁|降落|failsafe|超时","control":r"CTL_|MOT_|RC_|STAB|ACRO","network":r"web_rc|console|WIFI_|WiFi|192\.168"}.items():
    keys=[k for k in retained if re.search(rex,k,re.I)]
    matched=[k for k in keys if k in both]
    print(f"LITERAL_CATEGORY {cat}: {len(matched)}/{len(keys)}")

print("=== RELOCATION-TOLERANT EXACT MACHINE-BYTE SIGNATURES ===")
# Index 48-byte windows from reference at every byte position, but test only 1/16 rebuilt
# windows. A match is evidence that a byte run is identical somewhere, not equivalent behavior.
n=48
hashes=set()
for s in ref["segments"]:
    buf=s["data"]
    for i in range(0,max(0,len(buf)-n+1)):
        chunk=buf[i:i+n]
        if len(set(chunk))>=12:
            hashes.add(blake2s(chunk,digest_size=8).digest())
data=[]
for s in built["segments"]:
    buf=s["data"]; total=0; matched=0
    for i in range(0,max(0,len(buf)-n+1),16):
        chunk=buf[i:i+n]
        if len(set(chunk))<12:
            continue
        total+=1
        if blake2s(chunk,digest_size=8).digest() in hashes:
            matched+=1
    row={"built_load_address":f"0x{s['address']:x}","samples":total,"exact48B_spans_found_anywhere":matched,"ratio":round(matched/total,4) if total else None}
    print("SLIDING_MATCH="+json.dumps(row))
    data.append(row)
matched=sum(x["exact48B_spans_found_anywhere"] for x in data)
total=sum(x["samples"] for x in data)
print("RESULT_JSON="+json.dumps({
 "source_embedded_in_build":len(retained),"same_source_literals_in_reference":len(both),
 "missing_source_literals_in_reference":{k:v for k,v in list(missing.items())[:30]},
 "unaligned_48B_exact_window_overlap":round(matched/total,4) if total else None,
 "window_comparisons":total,"window_matches":matched,
 "caution":"A fingerprint comparison cannot prove functional or flight-safety equivalence."
 },ensure_ascii=False,separators=(",",":")))
