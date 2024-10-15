#!/usr/bin/env python3
from __future__ import annotations

import os
from mrcrowbar.lib.containers import mac
from mrcrowbar import utils

import machfs
import macresources

import argparse
import collections

ResourceFork = dict[bytes, dict[int, macresources.main.Resource]]

# make custom jank dump of code

SYSTEM_RAM_SIZE = 0x10000
DUMMY_ADDR = 0xFFFFFFFF

# m68k is big endian
u16 = utils.from_uint16_be
i16 = utils.from_int16_be
u32 = utils.from_uint32_be

to_u16 = utils.to_uint16_be
to_u32 = utils.to_uint32_be

def u16_to_i16(x: int) -> int:
    if x & 0x8000:
        x -= 0x10000
    return x


def get_file_from_volume(image_filename: str, path: list[str] | None) -> tuple[bytes, ResourceFork]:
    rsrcs: ResourceFork = collections.defaultdict(dict)

    with open(image_filename, "rb") as f:
        flat = f.read()
        v = machfs.Volume()
        v.read(flat)
        print(v)
        if not path:
            raise ValueError("Need to specify path")
        for p in path:
            v = v[p]
        for ax in macresources.parse_file(v.rsrc):
            rsrcs[ax.type][ax.id] = ax

        return v.data, rsrcs    


def get_file_from_macbinary(path: str) -> tuple[bytes, ResourceFork]:
    f = open(path, 'rb').read()
    mb = mac.MacBinary(f)    
    rsrcs: ResourceFork = collections.defaultdict(dict)
    for i in macresources.parse_file(mb.resource):
        rsrcs[i.type][i.id] = i

    return mb.data, rsrcs    


def dump_file(source: str, target: str, path: list[str] | None) -> None:
    print(f"dumping {':'.join([source]+(path if path else []))} to {target}")
    with open(source, "rb") as f:
        f.seek(122, os.SEEK_SET)
        mb_test = (u16(f.read(2)) & 0xfcff) == 0x8081
        f.seek(0x400, os.SEEK_SET)
        vol_test = f.read(2)

    if vol_test == b"BD" or vol_test == "H+":
        _, rsrcs = get_file_from_volume(source, path)
    elif mb_test:
        _, rsrcs = get_file_from_macbinary(source)
    else:
        raise ValueError(f"File {source} must be a HFS disk image or MacBinary file")
    return dump_file_from_resources(rsrcs, target)

def dump_file_from_resources(rsrcs: ResourceFork, out_filename: str) -> None:
    for rx in rsrcs:
        print(rx)
        for j, r in rsrcs[rx].items():
            if r.name != None:
                print(f"    {j}: {r.name}")
            else:
                print(f"    {j}")
    if b"CODE" in rsrcs:
        dump_file_from_code(rsrcs, out_filename)
    elif b"XCMD" in rsrcs:
        dump_file_from_xcmd(rsrcs, out_filename)


def dump_file_from_code(rsrcs: ResourceFork, out_filename: str) -> None:
    codes = rsrcs[b"CODE"]
    crels = rsrcs[b"CREL"]

    jumptable = codes[0]

    above_a5_size = u32(jumptable[:4])
    below_a5_size = u32(jumptable[4:8])
    jump_table_size = u32(jumptable[8:12])
    jump_table_offset = u32(jumptable[12:16])
    assert jump_table_size == len(jumptable) - 0x10
    assert jump_table_offset == 0x20

    a5 = below_a5_size + SYSTEM_RAM_SIZE
    for c in codes:
        if c == 0:
            continue
        a5 += len(codes[c]) - 4
    if b"STRS" in rsrcs:
        a5 += len(rsrcs[b"STRS"][0])

    dump = b""
    header = (
        b"J\xffA\xffN\xffK\xff"  # put garbage so address 0 isn't recognized as a string
    )
    # small function to force binary ninja to set the value of a5 as a global reg
    # move.l #a5_value, a5
    # rts
    header += b"\x2a\x7c" + to_u32(a5) + b"\x4e\x75"

    system_ram = bytearray(header + bytes(SYSTEM_RAM_SIZE - len(header)))
    system_ram[0x904:0x908] = to_u32(a5)
    dump += system_ram

    if b"STRS" in rsrcs:
        strs_base = len(dump)
        dump += rsrcs[b"STRS"][0]

    segment_bases = {}
    for c in codes:
        if c == 0:
            continue
        segment_header = codes[c][:4]
        segment_data = bytearray(codes[c][4:])
        segment_bases[c] = len(dump)
        first_jumptable_entry_offset = u16(segment_header[:2])
        needs_relocations = False
        if first_jumptable_entry_offset & 0x8000:
            first_jumptable_entry_offset &= ~0x8000
            needs_relocations = True
        jumptable_entry_num = u16(segment_header[2:])
        far_header = False
        if jumptable_entry_num & 0x8000:
            jumptable_entry_num &= ~0x8000
            far_header = True
        print(
            f"code segment {c}: first offset {first_jumptable_entry_offset:04x}, {jumptable_entry_num} jumptable entries",
            end="",
        )
        if needs_relocations:
            print(", reloc", end="")
        if far_header:
            print(", far", end="")
        print()
        # Think C (Symantec) relocations
        if needs_relocations and jumptable_entry_num > 0:
            # TODO: refactor
            for j in range(0, len(crels[c]), 2):
                addr = u16(crels[c][j : j + 2]) - 4  # -4 from header
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = addr & 0xFFFE
                else:
                    print("A5 patch ", end="")
                    base = a5
                data = u32(segment_data[addr : addr + 4])
                data2 = (data + base) & 0xFFFFFFFF
                segment_data[addr : addr + 4] = to_u32(data2)
                print(f"seg {c} addr {addr:04x} ({data:08x} -> {data2:08x})")
        dump += bytes(segment_data)

    # construct a5 world
    a5_world = b"\x00" * 32  # TODO pointer to quickdraw global vars
    for i in range(0x10, len(jumptable), 8):
        # construct a5 jumptable (all loaded jumptable entries)
        entry = jumptable[i : i + 8]
        if entry[2:4] == b"\x3f\x3c":
            """
            unloaded jumptable entry structure:
                XX XX: segment offset
                3f 3c XX XX: move.w SEGMENT_NUMBER, -(SP)
                    pushes SEGMENT_NUMBER onto the stack for _LoadSeg trap
                a9 f0: _LoadSeg trap number
            """
            segment_offset = u16(entry[:2])
            segment_num = u16(entry[4:6])
            if segment_num in segment_bases:
                addr = segment_bases[segment_num] + segment_offset
            else:
                print(
                    f"WARNING: code segment {segment_num} not found for jumptable entry {(i-0x10)//8}, replacing with dummy address"
                )
                addr = DUMMY_ADDR
        elif entry[2:4] == b"\x4e\xed":
            """
            preloaded? jumptable entry structure:
                XX XX: ???
                4e ed XX XX: jmp OFFSET(a5)
                4e 71: nop
            """
            offset = u16(entry[4:6])
            segment_num = 0  # dummy
            addr = offset + a5
        else:
            print(
                f"WARNING: unknown format for jumptable entry {(i-0x10)//8}, replacing with dummy address"
            )
            segment_num = 0  # dummy
            addr = DUMMY_ADDR
        a5_world += to_u16(segment_num)
        a5_world += b"\x4e\xf9"  # jmp
        a5_world += to_u32(addr)

    below_a5_data = bytes(below_a5_size)

    if b"ZERO" in rsrcs and b"DATA" in rsrcs:
        data_rsrc = bytes(rsrcs[b"DATA"][0])
        zero_rsrc = bytes(rsrcs[b"ZERO"][0])
        total_data_size = len(data_rsrc)
        for i in range(0, len(zero_rsrc), 2):
            total_data_size += u16(zero_rsrc[i : i + 2])
        if total_data_size <= below_a5_size:
            print("Adding DATA below A5 world")
            below_a5_data = bytearray()
            zero_index = 0
            for i in range(0, len(data_rsrc), 2):
                below_a5_data += data_rsrc[i : i + 2]
                if u16(data_rsrc[i : i + 2]) == 0:
                    below_a5_data += bytes(u16(zero_rsrc[zero_index : zero_index + 2]))
                    zero_index += 2
            # TODO refactor
            drel_rsrc = bytes(rsrcs[b"DREL"][0])
            i = 0
            while i < len(drel_rsrc):
                addr = i16(drel_rsrc[i : i + 2])
                if addr >= 0:
                    i += 2
                    addr = -u16(drel_rsrc[i : i + 2])
                if addr & 0x1:
                    print("STRS patch ", end="")
                    base = strs_base
                    addr = u16_to_i16(addr & 0xFFFE)
                else:
                    print("A5 patch ", end="")
                    base = a5
                addr += below_a5_size  # DREL relative to a5
                data = u32(below_a5_data[addr : addr + 4])
                data2 = (data + base) & 0xFFFFFFFF
                below_a5_data[addr : addr + 4] = to_u32(data2)
                print(f"data addr {addr:04x} ({data:08x} -> {data2:08x})")
                i += 2
            below_a5_data = bytes(below_a5_data) + bytes(
                below_a5_size - total_data_size
            )

    dump += below_a5_data
    assert len(dump) == a5
    dump += a5_world

    open(out_filename, "wb").write(dump)

def dump_file_from_xcmd(rsrcs: ResourceFork, out_filename: str) -> None:
    xcmds = rsrcs[b"XCMD"]
    
    a5 = SYSTEM_RAM_SIZE
    for c in xcmds:
        a5 += len(xcmds[c]) - 4

    dump = b""
    header = (
        b"J\xffA\xffN\xffK\xff"  # put garbage so address 0 isn't recognized as a string
    )
    # small function to force binary ninja to set the value of a5 as a global reg
    # move.l #a5_value, a5
    # rts
    header += b"\x2a\x7c" + to_u32(a5) + b"\x4e\x75"
    system_ram = bytearray(header + bytes(SYSTEM_RAM_SIZE - len(header)))
    system_ram[0x904:0x908] = to_u32(a5)
    dump += system_ram

    segment_bases = {}

    for c in xcmds:
        if c == 0:
            continue
        segment_data = bytearray(xcmds[c][4:])
        segment_bases[c] = len(dump)
        print(
            f"XCMD {c}: first offset {segment_bases[c]:04x}",
            end="",
        )
        dump += bytes(segment_data)

    # construct a5 world
    a5_world = b"\x00" * 32  # TODO pointer to quickdraw global vars

    assert len(dump) == a5
    dump += a5_world

    open(out_filename, "wb").write(dump)


def main():
    parser = argparse.ArgumentParser(description="Dump and preprocess M68K Macintosh code")
    parser.add_argument("source", help="Source file (disk image or MacBinary file)")
    parser.add_argument("target", help="Output file")
    parser.add_argument("--path", help="For disk images, path in the image to read (e.g. \"dir1:dir2:file\")")
    args = parser.parse_args()

    path = args.path.split(":") if args.path else None
    dump_file(args.source, args.target, path)


if __name__ == '__main__':
    main()

# dump_file('HeavenEarth13Color.toast', ['Heaven & Earth'], 'dump_heavenandearth')
# dump_file('disk2.dsk', ["System's Twilight"], 'dump_systemstwilight')
#dump_file("testfile.bin", ["Kid Pix"], "dump_kidpix")
