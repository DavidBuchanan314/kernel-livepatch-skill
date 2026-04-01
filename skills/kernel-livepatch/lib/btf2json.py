#!/usr/bin/env python3
"""Standalone BTF to JSON converter. Parses BTF binary format directly."""

import sys
import json
import struct
import argparse

BTF_MAGIC = 0xEB9F
ELF_MAGIC = b'\x7fELF'

KIND_NAMES = {
    0:  'UNKN',
    1:  'INT',
    2:  'PTR',
    3:  'ARRAY',
    4:  'STRUCT',
    5:  'UNION',
    6:  'ENUM',
    7:  'FWD',
    8:  'TYPEDEF',
    9:  'VOLATILE',
    10: 'CONST',
    11: 'RESTRICT',
    12: 'FUNC',
    13: 'FUNC_PROTO',
    14: 'VAR',
    15: 'DATASEC',
    16: 'FLOAT',
    17: 'DECL_TAG',
    18: 'TYPE_TAG',
    19: 'ENUM64',
}

FUNC_LINKAGE = {0: 'static', 1: 'global', 2: 'extern'}
VAR_LINKAGE  = {0: 'static', 1: 'global_allocated', 2: 'global_extern'}


def extract_btf_from_elf(data):
    """Extract raw BTF blob from .BTF ELF section."""
    if len(data) < 16:
        raise ValueError("Too short for ELF")

    ei_class = data[4]   # 1=32-bit, 2=64-bit
    ei_data  = data[5]   # 1=LE, 2=BE
    endian = '<' if ei_data == 1 else '>'
    bits64 = (ei_class == 2)

    if bits64:
        e_shoff, = struct.unpack_from(endian + 'Q', data, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + 'HHH', data, 58)
    else:
        e_shoff, = struct.unpack_from(endian + 'I', data, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + 'HHH', data, 46)

    # Read section name string table
    if bits64:
        sh_off = e_shoff + e_shstrndx * e_shentsize
        sh_offset, = struct.unpack_from(endian + 'Q', data, sh_off + 24)
        sh_size,   = struct.unpack_from(endian + 'Q', data, sh_off + 32)
    else:
        sh_off = e_shoff + e_shstrndx * e_shentsize
        sh_offset, = struct.unpack_from(endian + 'I', data, sh_off + 16)
        sh_size,   = struct.unpack_from(endian + 'I', data, sh_off + 20)

    shstrtab = data[sh_offset: sh_offset + sh_size]

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name_idx, = struct.unpack_from(endian + 'I', data, off)
        name_end = shstrtab.index(b'\x00', sh_name_idx)
        name = shstrtab[sh_name_idx:name_end].decode()
        if name == '.BTF':
            if bits64:
                sec_offset, = struct.unpack_from(endian + 'Q', data, off + 24)
                sec_size,   = struct.unpack_from(endian + 'Q', data, off + 32)
            else:
                sec_offset, = struct.unpack_from(endian + 'I', data, off + 16)
                sec_size,   = struct.unpack_from(endian + 'I', data, off + 20)
            return data[sec_offset: sec_offset + sec_size]

    raise ValueError("No .BTF section found in ELF file")


def get_str(strtab, off):
    if off == 0:
        return ''
    end = strtab.index(b'\x00', off)
    return strtab[off:end].decode(errors='replace')


def parse_btf(data):
    if data[:4] == ELF_MAGIC:
        data = extract_btf_from_elf(data)

    magic, version, flags, hdr_len = struct.unpack_from('<HBBI', data, 0)
    if magic != BTF_MAGIC:
        # try big-endian
        magic, version, flags, hdr_len = struct.unpack_from('>HBBI', data, 0)
        if magic != BTF_MAGIC:
            raise ValueError(f"Bad BTF magic: 0x{magic:04x}")
        endian = '>'
    else:
        endian = '<'

    U = endian + 'I'
    I = endian + 'i'

    type_off, type_len, str_off, str_len = struct.unpack_from(endian + 'IIII', data, 8)

    base = hdr_len
    type_data = data[base + type_off : base + type_off + type_len]
    str_data  = data[base + str_off  : base + str_off  + str_len]

    types = []
    pos = 0
    type_id = 1

    while pos < len(type_data):
        name_off, info, size_or_type = struct.unpack_from(endian + 'III', type_data, pos)
        pos += 12

        vlen      = info & 0xFFFF
        kind      = (info >> 24) & 0x1F
        kind_flag = (info >> 31) & 0x1

        name = get_str(str_data, name_off)
        kind_name = KIND_NAMES.get(kind, f'UNKNOWN_{kind}')

        t = {
            'id':        type_id,
            'kind':      kind_name,
            'name':      name or None,
            'kind_flag': bool(kind_flag),
        }

        if kind in (1, 4, 5, 6, 15, 16, 19):   # INT, STRUCT, UNION, ENUM, DATASEC, FLOAT, ENUM64 use size
            t['size'] = size_or_type
        elif kind == 3:                         # ARRAY: size/type unused
            pass
        elif kind in (2, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18):
            t['type_id'] = size_or_type or None

        # --- kind-specific extra data ---
        if kind == 1:  # INT
            extra, = struct.unpack_from(U, type_data, pos); pos += 4
            enc = (extra >> 24) & 0x0F
            t['int'] = {
                'encoding': {
                    'signed': bool(enc & 1),
                    'char':   bool(enc & 2),
                    'bool':   bool(enc & 4),
                },
                'offset': (extra >> 16) & 0xFF,
                'bits':   extra & 0xFF,
            }

        elif kind == 3:  # ARRAY
            arr_type, arr_index_type, arr_nelems = struct.unpack_from(endian + 'III', type_data, pos)
            pos += 12
            t['array'] = {
                'type_id':       arr_type,
                'index_type_id': arr_index_type,
                'nelems':        arr_nelems,
            }

        elif kind in (4, 5):  # STRUCT, UNION
            members = []
            for _ in range(vlen):
                m_name_off, m_type, m_offset = struct.unpack_from(endian + 'III', type_data, pos)
                pos += 12
                m = {
                    'name':    get_str(str_data, m_name_off) or None,
                    'type_id': m_type,
                }
                if kind_flag:
                    m['bitfield_size'] = (m_offset >> 24) & 0xFF
                    m['bit_offset']    = m_offset & 0xFFFFFF
                else:
                    m['bit_offset'] = m_offset
                members.append(m)
            t['members'] = members

        elif kind == 6:  # ENUM
            t['signed'] = bool(kind_flag)
            values = []
            for _ in range(vlen):
                v_name_off, = struct.unpack_from(U, type_data, pos); pos += 4
                v_val,      = struct.unpack_from(I, type_data, pos); pos += 4
                values.append({'name': get_str(str_data, v_name_off), 'val': v_val})
            t['values'] = values

        elif kind == 12:  # FUNC
            t['linkage'] = FUNC_LINKAGE.get(vlen, vlen)

        elif kind == 13:  # FUNC_PROTO
            params = []
            for _ in range(vlen):
                p_name_off, p_type = struct.unpack_from(endian + 'II', type_data, pos)
                pos += 8
                params.append({
                    'name':    get_str(str_data, p_name_off) or None,
                    'type_id': p_type or None,
                })
            t['params'] = params

        elif kind == 14:  # VAR
            linkage, = struct.unpack_from(U, type_data, pos); pos += 4
            t['linkage'] = VAR_LINKAGE.get(linkage, linkage)

        elif kind == 15:  # DATASEC
            vars_ = []
            for _ in range(vlen):
                vs_type, vs_offset, vs_size = struct.unpack_from(endian + 'III', type_data, pos)
                pos += 12
                vars_.append({'type_id': vs_type, 'offset': vs_offset, 'size': vs_size})
            t['vars'] = vars_

        elif kind == 17:  # DECL_TAG
            component_idx, = struct.unpack_from(I, type_data, pos); pos += 4
            t['component_idx'] = component_idx

        elif kind == 19:  # ENUM64
            t['signed'] = bool(kind_flag)
            values = []
            for _ in range(vlen):
                v_name_off, v_lo, v_hi = struct.unpack_from(endian + 'III', type_data, pos)
                pos += 12
                val = v_lo | (v_hi << 32)
                if kind_flag and v_hi & 0x80000000:
                    val -= 1 << 64
                values.append({'name': get_str(str_data, v_name_off), 'val': val})
            t['values'] = values

        types.append(t)
        type_id += 1

    return {
        'header': {
            'magic':   f'0x{magic:04x}',
            'version': version,
            'flags':   flags,
            'hdr_len': hdr_len,
        },
        'types': types,
    }


def main():
    ap = argparse.ArgumentParser(description='Convert BTF binary to JSON')
    ap.add_argument('file', nargs='?', default='/sys/kernel/btf/vmlinux',
                    help='BTF file or ELF with .BTF section (default: /sys/kernel/btf/vmlinux)')
    ap.add_argument('--indent', type=int, default=2, help='JSON indent (0 = compact)')
    args = ap.parse_args()

    with open(args.file, 'rb') as f:
        data = f.read()

    result = parse_btf(data)
    indent = args.indent if args.indent > 0 else None
    json.dump(result, sys.stdout, indent=indent)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
