#!/usr/bin/env python3
"""Decode ESP-IDF 32-byte partition records directly from flashed 4MiB images."""
from pathlib import Path
import struct,json
paths={
    "original":Path("Firmware/XW-Drone.ino.merged.bin"),
    "linux":Path("build-linux/XW-Drone.ino.merged.bin"),
    "windows":Path("build-windows/XW-Drone.ino.merged.bin"),
}
def decode(image):
    area=image[0x8000:0x9000]
    records=[]
    for ofs in range(0,len(area),32):
        part=area[ofs:ofs+32]
        if part[:2]==b"\xff\xff":break
        if part[:2]==b"\xeb\xeb":
            print("Found MD5-signature entry");break
        if part[:2]!=b"\xaa\x50":
            raise ValueError(f"Unexpected magic at offset 0x{0x8000+ofs:x}: {part[:2].hex()}")
        magic, typ, subtype, flash_offset, size, label, flags=struct.unpack("<HBBII16sI",part)
        name=label.split(b"\x00",1)[0].decode("utf-8","replace")
        kind={0:"app",1:"data"}.get(typ,"type_"+hex(typ))
        sub={ (0,0):"factory",(1,2):"nvs",(1,1):"phy",(1,0):"otadata",
             (1,0x82):"spiffs",(1,0x83):"fat",(1,0x84):"littlefs"}.get((typ,subtype),
             f"0x{subtype:02x}"+(" (OTA app)" if typ==0 and 0x10<=subtype<=0x1f else ""))
        records.append({"name":name,"type":kind,"subtype":sub,
                        "offset":f"0x{flash_offset:x}","size_bytes":size,
                        "end":f"0x{flash_offset+size:x}","flags":f"0x{flags:x}"})
    return records
parsed={}
for n,p in paths.items():
    parsed[n]=decode(p.read_bytes())
    print("PARTITIONS_"+n+"="+json.dumps(parsed[n],separators=(",",":"),ensure_ascii=False))
print("PARTITION_ORIGINAL_VS_LINUX_EQUAL="+str(parsed["original"]==parsed["linux"]))
print("PARTITION_ORIGINAL_VS_WINDOWS_EQUAL="+str(parsed["original"]==parsed["windows"]))
print("PARTITION_LINUX_VS_WINDOWS_EQUAL="+str(parsed["linux"]==parsed["windows"]))
Path("comparison").mkdir(exist_ok=True)
Path("comparison/partition-layout.json").write_text(json.dumps(parsed,ensure_ascii=False,indent=2),encoding="utf-8")
out=["# Parsed ESP32 partition tables","",
     "Partition entries were parsed directly from offset 0x8000 of each 4MiB merged image.",
     ""]
for n,parts in parsed.items():
    out.extend(["## "+n,"","| Name | Type | Subtype | Start | End | Size |","|---|---|---|---|---|---:|"])
    for x in parts:
        out.append(f"| {x['name']} | {x['type']} | {x['subtype']} | {x['offset']} | {x['end']} | {x['size_bytes']} |")
    out.append("")
out+=["## Safety note","","A mismatched flash layout can affect persistent Preferences/NVS, OTA slots and whether a firmware image fits its application partition. Do not flash a newly merged image to a working drone without verifying the specific board and configuration backup."]
Path("comparison/partition-layout.md").write_text("\n".join(out)+"\n",encoding="utf-8")
