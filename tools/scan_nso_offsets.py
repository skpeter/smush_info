"""Find every smush_info hook and data offset in a Smash Ultimate main NSO.

The code patterns are the same bytes src/lib.rs searches for, plus anchors for
the offsets that file still hardcodes. Run this on the next update's main and
paste the printed values back into lib.rs.

  python tools/scan_nso_offsets.py <main-nso>

The NSO may be compressed. Requires the lz4 package. capstone is optional and
only used to print the instruction at each hook.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

TEXT_FLAG = 1
RO_FLAG = 2
DATA_FLAG = 4

# (name, needle, delta, how the plugin uses it)
CODE_PATTERNS = [
    (
        "FIGHTER_SELECTED",
        bytes([0xA8, 0x66, 0x40, 0xB9, 0x08, 0x01, 0x00, 0x32, 0xE0, 0x03, 0x17, 0xAA, 0xA8, 0x66, 0x00, 0xB9]),
        0x10,
        "runtime search, hook is the following BL",
    ),
    (
        "OFFSET1",
        bytes([0x81, 0x0E, 0x40, 0xF9, 0xE0, 0x03, 0x16, 0xAA]),
        0x38,
        "runtime search",
    ),
    (
        "OFFSET2",
        bytes([0x60, 0x02, 0x00, 0xB4, 0x14, 0x58, 0x40, 0xA9]),
        -0xC,
        "runtime search",
    ),
    (
        "OFFSET3",
        bytes([
            0xFF, 0x83, 0x01, 0xD1, 0xF6, 0x57, 0x03, 0xA9, 0xF4, 0x4F, 0x04, 0xA9,
            0xFD, 0x7B, 0x05, 0xA9, 0xFD, 0x43, 0x01, 0x91, 0x15, 0x44, 0x40, 0xF9,
        ]),
        0,
        "runtime search",
    ),
    (
        "UPDATE_TAG_FOR_PLAYER",
        bytes([
            0xFF, 0x43, 0x01, 0xD1, 0xF4, 0x4F, 0x03, 0xA9, 0xFD, 0x7B, 0x04, 0xA9,
            0xFD, 0x03, 0x01, 0x91, 0x28, 0x00, 0x40, 0xB9, 0x08, 0x48, 0x02, 0xB9,
        ]),
        0,
        "hardcoded in lib.rs",
    ),
    (
        "STAGE_SELECTED",
        bytes([0xE8, 0x03, 0x00, 0x32, 0x68, 0x32, 0x00, 0xB9, 0xFD, 0x7B, 0x4B, 0xA9, 0xF4, 0x4F, 0x4A, 0xA9, 0xFF, 0x03, 0x03, 0x91]),
        -4,
        "hardcoded in lib.rs, hook is the BL just before this epilogue",
    ),
    (
        # void submit(Task* this). When [this+0xfc] is 0 it builds
        # save:/save_data/replay/...replay....bin and enqueues it. The ADRP of
        # that directory is inside an earlier state, not this entry.
        # Same text offset on 13.0.4 and 13.0.5.
        "REPLAY_SUBMIT",
        bytes([
            0xFC, 0x67, 0xBB, 0xA9, 0xF8, 0x5F, 0x01, 0xA9, 0xF6, 0x57, 0x02, 0xA9,
            0xF4, 0x4F, 0x03, 0xA9, 0xFD, 0x7B, 0x04, 0xA9, 0xFD, 0x03, 0x01, 0x91,
            0xFF, 0x03, 0x0C, 0xD1, 0x08, 0xFC, 0x40, 0xB9,
        ]),
        0,
        "one argument in x0. Task comes from REPLAY_TASK_SLOT",
    ),
    (
        # void ctor(Box*). Allocates the task (align 16, size 0x1a0) and stores it
        # in the box. The BL at +0x1c is the allocator the menu also uses for the box.
        "REPLAY_TASK_CTOR",
        bytes([
            0xFF, 0xC3, 0x00, 0xD1, 0xF4, 0x4F, 0x01, 0xA9, 0xFD, 0x7B, 0x02, 0xA9,
            0xFD, 0x83, 0x00, 0x91, 0xF3, 0x03, 0x00, 0xAA, 0x01, 0x34, 0x80, 0x52,
            0xE0, 0x03, 0x1C, 0x32,
        ]),
        0,
        "menu calls this after alloc(0x10, 8). BL at +0x1c is the allocator",
    ),
    (
        # Results pump. The menu calls this once a frame after the constructor.
        "REPLAY_TASK_PUMP",
        bytes([
            0xF3, 0x0F, 0x1E, 0xF8, 0xFD, 0x7B, 0x01, 0xA9, 0xFD, 0x43, 0x00, 0x91,
            0x08, 0xF4, 0x80, 0xB9, 0x1F, 0x4D, 0x00, 0x71, 0x42, 0x07, 0x00, 0x54,
            0x08, 0x08, 0x08, 0x8B, 0x08, 0xA9, 0x40, 0xB9,
        ]),
        0,
        "one argument in x0, the task. Same text offset on 13.0.4 and 13.0.5",
    ),
]

# ldr x8, [x8, #0xf0]; add x0, x8, #0x588; ldr x8, [x8, #0x588]; ldr x8, [x8, #0x18]
# The ADRP of the replay manager is the instruction immediately before this.
# Every site names the same global. The menu calls vtable+0x18 and stores at task+0x198.
REPLAY_SOURCE_LOAD = bytes([
    0x08, 0x79, 0x40, 0xF9, 0x00, 0x21, 0x16, 0x91, 0x08, 0xC5, 0x42, 0xF9, 0x08, 0x0D, 0x40, 0xF9,
])

# ldr x8, [x8, #0x5b8]; mov x19, x0; ldr x0, [x8]
# The ADRP of the task box is the instruction immediately before this.
# 13.0.5 has two copies (results update); both name the same slot.
REPLAY_TASK_SLOT = bytes([0x08, 0xDD, 0x42, 0xF9, 0xF3, 0x03, 0x00, 0xAA, 0x00, 0x01, 0x40, 0xF9])

# Stable instructions immediately before an ADRP of that global.
# 13.0.4 and 13.0.5 keep PLAYER_TAG 0x4EDB8 bytes below PLAYER_SAVE. The tag
# array has no ADRP of its own, so it is reported from that gap.
DATA_ANCHORS = [
    (
        "PLAYER_SAVE",
        bytes([0x08, 0x20, 0x40, 0x39, 0xF3, 0x03, 0x01, 0xAA, 0xF4, 0x03, 0x00, 0xAA]),
    ),
    (
        "MENU",
        bytes([0x08, 0x05, 0x40, 0xF9, 0x08, 0x75, 0x5C, 0x39, 0x1F, 0x01, 0x00, 0x71, 0xE8, 0x07, 0x9F, 0x1A]),
    ),
]
SAVE_TO_TAG = 0x4EDB8


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    hits = []
    start = 0
    while True:
        found = haystack.find(needle, start)
        if found < 0:
            return hits
        hits.append(found)
        start = found + 1


def decompress_segment(blob: bytes, decoded_size: int, compressed: bool) -> bytes:
    if not compressed:
        return blob[:decoded_size]
    import lz4.block

    return lz4.block.decompress(blob, uncompressed_size=decoded_size)


def load_nso(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:4] != b"NSO0":
        raise SystemExit(f"{path} is not an NSO (magic {raw[:4]!r})")
    flags = u32(raw, 0xC)
    segments = {}
    for name, base, flag in (("text", 0x10, TEXT_FLAG), ("ro", 0x20, RO_FLAG), ("data", 0x30, DATA_FLAG)):
        file_off = u32(raw, base)
        mem_off = u32(raw, base + 4)
        dec_size = u32(raw, base + 8)
        comp_size = u32(raw, 0x60 + (0 if name == "text" else 4 if name == "ro" else 8))
        blob = raw[file_off : file_off + comp_size]
        decoded = decompress_segment(blob, dec_size, bool(flags & flag))
        if len(decoded) != dec_size:
            raise SystemExit(f"{name} decoded to {len(decoded)} bytes, header says {dec_size}")
        segments[name] = {"mem": mem_off, "data": decoded}
    bss_size = u32(raw, 0x3C)
    image_size = segments["data"]["mem"] + len(segments["data"]["data"]) + bss_size
    return {
        "text": segments["text"]["data"],
        "ro_mem": segments["ro"]["mem"],
        "data_mem": segments["data"]["mem"],
        "data_end": segments["data"]["mem"] + len(segments["data"]["data"]),
        "bss_end": image_size,
    }


def section_of(nso: dict, off: int) -> str:
    if 0 <= off < nso["ro_mem"]:
        return "text"
    if nso["ro_mem"] <= off < nso["data_mem"]:
        return "rodata"
    if nso["data_mem"] <= off < nso["data_end"]:
        return "data"
    if nso["data_end"] <= off < nso["bss_end"]:
        return "bss"
    return "outside the image"


def adrp_page(off: int, word: int) -> int:
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (off & ~0xFFF) + (imm << 12)


def add_or_ldr_offset(word: int) -> int | None:
    if (word & 0xFF800000) == 0x91000000 and ((word >> 22) & 3) == 0:
        return (word >> 10) & 0xFFF
    if (word & 0xFFC00000) == 0xF9400000:
        return ((word >> 10) & 0xFFF) * 8
    if (word & 0xFFC00000) == 0xB9400000:
        return ((word >> 10) & 0xFFF) * 4
    return None


def address_after_anchor(text: bytes, anchor_end: int) -> int | None:
    """Decode the first ADRP + ADD/LDR pair in the next few instructions."""
    for off in range(anchor_end, min(anchor_end + 0x20, len(text) - 8), 4):
        word = u32(text, off)
        if (word & 0x9F000000) != 0x90000000:
            continue
        reg = word & 0x1F
        follow = u32(text, off + 4)
        extra = add_or_ldr_offset(follow)
        if extra is None:
            continue
        base_reg = (follow >> 5) & 0x1F
        if base_reg != reg:
            continue
        return adrp_page(off, word) + extra
    return None


def insn_at(text: bytes, off: int) -> str:
    if off < 0 or off + 4 > len(text):
        return ""
    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
    except ImportError:
        return ""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoded = list(md.disasm(text[off : off + 4], off))
    if not decoded:
        return ""
    insn = decoded[0]
    return f"{insn.mnemonic} {insn.op_str}".rstrip()


def report_code(text: bytes, name: str, needle: bytes, delta: int, note: str) -> int | None:
    hits = find_all(text, needle)
    if len(hits) != 1:
        print(f"  {name:<24} {len(hits)} hits  {note}")
        return None
    hook = hits[0] + delta
    shown = insn_at(text, hook)
    extra = f"  {shown}" if shown else ""
    print(f"  {name:<24} 0x{hook:x}  {note}{extra}")
    return hook


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/scan_nso_offsets.py <main-nso>")
    nso = load_nso(Path(sys.argv[1]))
    text = nso["text"]
    print(f"text 0x{len(text):x}  bss end 0x{nso['bss_end']:x}")
    print()
    print("code hooks")
    for name, needle, delta, note in CODE_PATTERNS:
        hook = report_code(text, name, needle, delta, note)
        if name == "REPLAY_TASK_CTOR" and hook is not None:
            bl = hook + 0x1C
            word = u32(text, bl)
            if (word & 0xFC000000) == 0x94000000:
                imm = word & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                alloc = (bl + imm * 4) & 0xFFFFFFFF
                print(
                    f"  {'REPLAY_TASK_ALLOC':<24} 0x{alloc:x}  "
                    "alloc(align, size), from the ctor's BL"
                )

    print()
    print("data offsets")
    found = {}
    for name, needle in DATA_ANCHORS:
        hits = find_all(text, needle)
        if len(hits) != 1:
            print(f"  {name:<24} {len(hits)} anchor hits")
            continue
        addr = address_after_anchor(text, hits[0] + len(needle))
        if addr is None:
            print(f"  {name:<24} anchor matched, ADRP not found")
            continue
        found[name] = addr
        print(f"  {name:<24} 0x{addr:x}  {section_of(nso, addr)}  hardcoded in lib.rs")

    save = found.get("PLAYER_SAVE")
    if save is None:
        print(f"  {'PLAYER_TAG':<24} not derived, PLAYER_SAVE anchor missed")
    else:
        tag = save - SAVE_TO_TAG
        print(
            f"  {'PLAYER_TAG':<24} 0x{tag:x}  {section_of(nso, tag)}  "
            f"PLAYER_SAVE - 0x{SAVE_TO_TAG:x} (same gap in 13.0.4 and 13.0.5)"
        )
        menu = found.get("MENU")
        if menu is not None:
            print(f"  gap SAVE-MENU 0x{save - menu:x}  gap SAVE-TAG 0x{save - tag:x}")

    print()
    print("replay save")
    slots = []
    for hit in find_all(text, REPLAY_TASK_SLOT):
        adrp = hit - 4
        if adrp < 0:
            continue
        word = u32(text, adrp)
        if (word & 0x9F000000) != 0x90000000 or (word & 0x1F) != 8:
            continue
        slots.append(adrp_page(adrp, word) + 0x5B8)
    if not slots:
        print("  REPLAY_TASK_SLOT         0 hits")
    elif any(slot != slots[0] for slot in slots):
        print(f"  REPLAY_TASK_SLOT         {len(slots)} disagreeing hits")
    else:
        slot = slots[0]
        print(
            f"  {'REPLAY_TASK_SLOT':<24} 0x{slot:x}  {section_of(nso, slot)}  "
            f"{len(slots)} sites. task = *(u64*)(*(u64*)slot)"
        )

    sources = []
    for hit in find_all(text, REPLAY_SOURCE_LOAD):
        adrp = hit - 4
        if adrp < 0:
            continue
        word = u32(text, adrp)
        if (word & 0x9F000000) != 0x90000000 or (word & 0x1F) != 8:
            continue
        sources.append(adrp_page(adrp, word) + 0xF0)
    if not sources:
        print("  REPLAY_SOURCE            0 hits")
    elif any(src != sources[0] for src in sources):
        print(f"  REPLAY_SOURCE            {len(sources)} disagreeing hits")
    else:
        src = sources[0]
        print(
            f"  {'REPLAY_SOURCE':<24} 0x{src:x}  {section_of(nso, src)}  "
            f"{len(sources)} sites. *(u64*)slot is the replay manager"
        )


if __name__ == "__main__":
    main()
