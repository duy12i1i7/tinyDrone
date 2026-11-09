#!/usr/bin/env python3
"""Reproducible three-way static comparison of ESP32 firmware binary artifacts.

Inputs: original merged image from repository, Linux merged/app from this run,
and Windows merged/app from a pinned, previously successful GitHub Actions run.
This is evidence about binary identity and features, NOT runtime equivalence.
"""
from pathlib import Path
from hashlib import sha256, blake2s
import json, re, struct, itertools

BIN = {
    "original": {
        "merged": Path("Firmware/XW-Drone.ino.merged.bin"),
        "app": None,
    },
    "linux": {
        "merged": Path("build-linux/XW-Drone.ino.merged.bin"),
        "app": Path("build-linux/XW-Drone.ino.bin"),
    },
    "windows": {
        "merged": Path("build-windows/XW-Drone.ino.merged.bin"),
        "app": Path("build-windows/XW-Drone.ino.bin"),
    },
}
OFFSET=0x10000
def hexsha(x): return sha256(x).hexdigest()

def image_parse(data):
    if not data or data[0]!=0xe9:
        raise ValueError("Expected ESP32 image at application offset; magic E9 missing")
    n=data[1]
    if n<1 or n>16: raise ValueError("Invalid segment count")
    pos=24
    segments=[]
    for i in range(n):
        address, size=struct.unpack_from("<II",data,pos)
        pos+=8
        if size>len(data)-pos: raise ValueError("Segment truncated")
        segments.append({"address":address,"size":size,"data":data[pos:pos+size]})
        pos+=size
    return {
        "header":data[:24].hex(),
        "entry":f"0x{struct.unpack_from('<I',data,4)[0]:08x}",
        "segments":segments,
        "segments_end":pos,
        "app_binary":data[:pos]
    }

def descriptor(data):
    offset=data.find(struct.pack("<I",0xABCD5432),0,min(len(data),65536))
    if offset<0: return {}
    def f(i,n):return data[offset+i:offset+i+n].split(b"\0",1)[0].decode("utf-8","replace")
    return {"project":f(48,32),"version":f(16,32),"build_date":f(96,16),
            "build_time":f(80,16),"idf_version":f(112,32),
            "elf_sha256":data[offset+144:offset+176].hex()}
def strings(data):
    return {x.decode("ascii","ignore") for x in re.findall(rb"[\x20-\x7e]{7,}",data)}
def sample_spans(image,n=48,stride=16):
    for seg in image["segments"]:
        data=seg["data"]
        for pos in range(0,len(data)-n+1,stride):
            v=data[pos:pos+n]
            if len(set(v))>=12:yield v
def fingerprints(a,b,n=48):
    # Build a rolling exact-window index of the first app to avoid alignment bias.
    idx=set()
    for s in a["segments"]:
        d=s["data"]
        for pos in range(0,len(d)-n+1):
            sub=d[pos:pos+n]
            if len(set(sub))>=12:
                idx.add(blake2s(sub,digest_size=8).digest())
    hits,total=0,0
    for v in sample_spans(b,n):
        total+=1
        if blake2s(v,digest_size=8).digest() in idx:
            hits+=1
    return {"from": "second image sampled","matched":hits,"samples":total,
            "fraction":round(hits/total,6) if total else None,
            "definition":"48-byte windows from second image observed anywhere in first image"}

loaded={}
for k, paths in BIN.items():
    merged=paths["merged"].read_bytes()
    app=(paths["app"].read_bytes() if paths["app"] is not None else merged[OFFSET:])
    parsed=image_parse(app)
    loaded[k]={"merged":merged,"app":app,"parsed":parsed,
               "descriptor":descriptor(app),
               "strings":strings(parsed["app_binary"])}
    print(f"IMAGE {k}: merged_size={len(merged)} merged_sha256={hexsha(merged)} "
          f"app_size={len(app) if paths['app'] else '(embedded, unpadded parsed bytes='+str(parsed['segments_end'])+')'} "
          f"app_sha256={hexsha(app[:parsed['segments_end']])}")
    print(f"DESC {k}: {json.dumps(loaded[k]['descriptor'])}")
    print(f"ENTRY {k}: {parsed['entry']}, {len(parsed['segments'])} segments")
    for n, s in enumerate(parsed["segments"]):
        print(f"SEGMENT {k} [{n}]: address=0x{s['address']:08x} size={s['size']} "
              f"sha256={hexsha(s['data'])}")

pairs={}
for name1,name2 in itertools.combinations(loaded,2):
    a,b=loaded[name1],loaded[name2]
    x,y=a["merged"],b["merged"]
    image_bytes_equal=sum(z==w for z,w in zip(x,y))
    non_padding_union=sum(z!=0xff or w!=0xff for z,w in zip(x,y))
    distinct_non_padding=sum(z!=w and (z!=0xff or w!=0xff) for z,w in zip(x,y))
    both_app=a["parsed"]["app_binary"], b["parsed"]["app_binary"]
    app_len=min(len(both_app[0]),len(both_app[1]))
    app_equal=sum(z==w for z,w in zip(both_app[0][:app_len],both_app[1][:app_len]))
    shared_strings=a["strings"]&b["strings"]
    fp=fingerprints(a["parsed"],b["parsed"])
    pair={
        "merged_equal":x==y,
        "merged_same_position_equal_fraction":round(image_bytes_equal/min(len(x),len(y)),6),
        "non_ff_bytes_union":non_padding_union,
        "differing_bytes_excluding_ff_ff":distinct_non_padding,
        "app_parsed_equal":both_app[0]==both_app[1],
        "app_same_position_equal_fraction":round(app_equal/app_len,6),
        "app_parsed_sizes":[len(z) for z in both_app],
        "shared_ascii_strings":len(shared_strings),
        "strings_count":[len(a["strings"]),len(b["strings"])],
        "exact48B_overlaps":fp,
        "note":"Binary byte/string similarity is not functional-equivalence evidence by itself.",
    }
    pairs[name1+"_vs_"+name2]=pair
    print("PAIR "+name1+"_vs_"+name2+": "+json.dumps(pair,separators=(",",":")))

# Confirm exact source Web RC HTML is in all apps.
h=Path("src/XW-Drone/web_rc_html.h").read_text(encoding="utf-8")
m=re.search(r'R"rawliteral\((.*?)\)rawliteral"',h,re.S)
html=m.group(1).encode("utf-8") if m else b""
html_presence={k:bool(html) and html in d["parsed"]["app_binary"] for k,d in loaded.items()}
print("HTML_MATCH="+json.dumps({"html_bytes":len(html),"source_html_in_each":html_presence}))
chosen_literals=[
    "/web_rc","/web_rc/status","/web_rc/heartbeat","/console/cmd",
    "CTL_R_RATE_P","CTL_P_RATE_P","CTL_Y_RATE_P","MOT_PIN_FL",
    "MOT_PIN_RR","IMU_ROT_ROLL","WIFI_AP_SSID","XW_Drone_WiFi",
]
fingerprints_out={s:{k:s.encode() in d["parsed"]["app_binary"] for k,d in loaded.items()} for s in chosen_literals}
print("FUNCTION_MARKERS="+json.dumps(fingerprints_out,ensure_ascii=False))

summary={
    "variants":{k:{
        "full_sha256":hexsha(d["merged"]),"size":len(d["merged"]),
        "parsed_app_sha256":hexsha(d["parsed"]["app_binary"]),
        "parsed_app_size":len(d["parsed"]["app_binary"]),
        "app_input_file_size":len(d["app"]),
        "entry":d["parsed"]["entry"], "descriptor":d["descriptor"],
        "segment_sizes":[{"address":f"0x{s['address']:08x}","size":s["size"],"sha256":hexsha(s["data"])}
                         for s in d["parsed"]["segments"]],
        "ascii_strings":len(d["strings"])
    } for k,d in loaded.items()},
    "comparisons":pairs,
    "exact_source_html_in":html_presence,
    "html_bytes":len(html),
    "markers":fingerprints_out,
}
out=Path("comparison")
out.mkdir(exist_ok=True)
(out/"firmware-three-way.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")

md=["# tinyDrone three-way ESP32 binary comparison","","All three inputs use the same Git source checkout; Linux and Windows builds compile with ESP32 core 3.3.1 and FlixPeriph 1.10.3 / MAVLink 2.0.33.",
    "",
    "## Full merged images","","| Image | Size | SHA-256 | Application parsed size | Entry address |",
    "|---|---:|---|---:|---|"]
for k,v in summary["variants"].items():
    md.append(f"| {k} | {v['size']} | \x60{v['full_sha256']}\x60 | {v['parsed_app_size']} | {v['entry']} |")
md.extend(["","## Pairwise comparisons","",
           "| Pair | Full binary identical | Parsed application identical | Exact 48-byte sample windows observed in first image | Shared ASCII strings |",
           "|---|---|---|---:|---:|"])
for k,v in pairs.items():
    w=v["exact48B_overlaps"]
    md.append(f"| {k} | {v['merged_equal']} | {v['app_parsed_equal']} | {w['matched']}/{w['samples']} ({w['fraction']*100:.2f}%) | {v['shared_ascii_strings']} |")
md.extend(["","## ESP32 application descriptors"])
for k,v in summary["variants"].items():
    md.append(f"- **{k}**: \x60{json.dumps(v['descriptor'],ensure_ascii=False)}\x60")
md.extend(["","## Segments"])
for k,v in summary["variants"].items():
    md.append(f"### {k}")
    md.append("| Load address | Size (bytes) | SHA-256 |")
    md.append("|---|---:|---|")
    for seg in v["segment_sizes"]:
        md.append(f"| \x60{seg['address']}\x60 | {seg['size']} | \x60{seg['sha256']}\x60 |")
md.extend(["","## Embedded UI and feature markers",
           f"Exact source HTML bytes: **{len(html)}**.",
           f"Source HTML present: \x60{json.dumps(html_presence)}\x60",
           f"All tested feature markers present across all images: **{all(all(v.values()) for v in fingerprints_out.values())}**.",
           "",
           "## Limits",
           "Matching strings, UI, or code byte signatures does not prove identical PID, safety, timing, or behavior on drone hardware.",
           "The byte overlap statistic is a diagnostic fingerprint, not a percentage of matching functionality.",
           "Output includes build-specific metadata and paths; original toolchain and board options remain uncertain.",
           ])
(out/"firmware-three-way.md").write_text("\n".join(md)+"\n",encoding="utf-8")
print("REPORT_JSON="+str(out/"firmware-three-way.json"))
print("REPORT_MARKDOWN="+str(out/"firmware-three-way.md"))
