#!/usr/bin/env python3
"""Triangular flash-layout forensic comparison of original, Linux, Windows ESP32 merged bins.

Reports exact bytes by flash address, bootloader and partition identity, app
header/descriptor, strings exclusively present, and likely source risks.
Byte comparison cannot establish functional equivalence.
"""
import hashlib, json, re, struct
from pathlib import Path
P={
 "original":Path("Firmware/XW-Drone.ino.merged.bin"),
 "linux":Path("build-linux/XW-Drone.ino.merged.bin"),
 "windows":Path("build-windows/XW-Drone.ino.merged.bin"),
}
OUT=Path("comparison")
OUT.mkdir(parents=True,exist_ok=True)
data={n:p.read_bytes() for n,p in P.items()}
def digest(v):return hashlib.sha256(v).hexdigest()
def asciis(b):return set(x.decode("ascii","replace") for x in re.findall(rb"[\x20-\x7e]{7,}",b))
def binstrings(b):
    # Unicode UTF-8 strings may contain Chinese; ASCII-only output remains robust.
    return asciis(b)
def app_length(b):
    a=b[0x10000:]
    if len(a)<24 or a[0]!=0xE9:return None
    n=a[1];pos=24
    for j in range(n):
        addr,size=struct.unpack_from("<II",a,pos)
        pos+=8+size
        if pos>len(a):return None
    return pos
def diff_index(x,y):
    return next((i for i,(a,b) in enumerate(zip(x,y)) if a!=b),None)
regions=[
 ("flash_header_0_to_bootloader",0x0,0x1000),
 ("bootloader_area",0x1000,0x8000),
 ("partition_table_area",0x8000,0x9000),
 ("flash_reserved",0x9000,0xe000),
 ("boot_app_data",0xe000,0x10000),
 ("application_area",0x10000,0x200000),
 ("upper_flash",0x200000,0x400000),
]
result={"regions":{},"pairs":{},"original_extra_ascii_project_like":[]}
for name,lo,hi in regions:
    row={"start":hex(lo),"end":hex(hi),"bytes":hi-lo}
    for n,b in data.items():
        sub=b[lo:hi]
        row[n]={"sha256":digest(sub),"non_ff_bytes":sum(c!=0xff for c in sub)}
    row["all_equal"]=(data["original"][lo:hi]==data["linux"][lo:hi]==data["windows"][lo:hi])
    result["regions"][name]=row
    print("REGION "+name+" "+json.dumps(row,separators=(",",":")))
for a,b in [("original","linux"),("original","windows"),("linux","windows")]:
    x,y=data[a],data[b]; d=diff_index(x,y)
    regionlist=[]
    for name,lo,hi in regions:
        xx,yy=x[lo:hi],y[lo:hi]
        unequal=sum(v!=w for v,w in zip(xx,yy))
        regionlist.append({"region":name,"diff_bytes":unequal,"total_bytes":hi-lo,
                          "first_diff_absolute_address":hex(lo+diff_index(xx,yy)) if unequal else None})
    row={"first_diff_addr":hex(d) if d is not None else None,"regions":regionlist,
         "same_first_64KiB":x[:0x10000]==y[:0x10000]}
    result["pairs"][a+"_vs_"+b]=row
    print("REGION_PAIR "+a+"_vs_"+b+" "+json.dumps(row,separators=(",",":")))
appbytes={k:b[0x10000:0x10000+app_length(b)] for k,b in data.items()}
strs={k:binstrings(v) for k,v in appbytes.items()}
miss=strs["original"]-strs["windows"]-strs["linux"]
only_win=strs["windows"]-strs["original"]
only_lin=strs["linux"]-strs["original"]
select=lambda x: bool(re.search(r"board|GPIO|MOT_|IMU_|CTL_|SF_|SBUS|Web RC|wifi|WiFi|battery|PWM|PID|Parsing.cpp|[A-Za-z]:\\",x,re.I))
for n,items in [("orig_only",miss),("windows_only",only_win),("linux_only",only_lin)]:
    d=sorted(filter(select,items))
    result[n]=d[:100]
    print("UNIQUE "+n+" "+json.dumps({"count":len(items),"selected":d[:30]},ensure_ascii=False))
Path("comparison/flash-region-analysis.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
lines=["# ESP32 flash-region forensic comparison","","Pairwise exact byte comparisons (0x1000 bootloader, 0x8000 partition, 0x10000 application).",
       "Regions are flash address ranges, not necessarily only one logical binary component.","",
       "| Region | Hex span | Bytes | All three identical? |",
       "|---|---|---:|---|"]
for k,v in result["regions"].items():
    lines.append(f"| {k} | {v['start']}–{v['end']} | {v['bytes']} | {v['all_equal']} |")
for pair,row in result["pairs"].items():
    lines+=["",f"## {pair}","",f"Same first 64KiB: {row['same_first_64KiB']}; first difference at {row['first_diff_addr']}.",
            "","| Region | Different bytes | First different flash offset |","|---|---:|---|"]
    for r in row["regions"]:
        lines.append(f"| {r['region']} | {r['diff_bytes']} | {r['first_diff_absolute_address']} |")
lines+=["","## Important caution","The byte differences do not identify PID, motor command, IMU calibration, or failsafe functional differences without matched debug symbols or actual hardware tests.","",
        "ESP32 application and flash offsets are layout assumptions appropriate to this original merged image and chosen ESP32 Dev Module board.","",
        "Comparison is reproducible using artifacts from the successful Linux three-way run and Windows run."]
Path("comparison/flash-region-analysis.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
