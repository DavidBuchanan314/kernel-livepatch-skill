"""Parse /proc/kallsyms and dump kernel text and data sections via /proc/kcore."""

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'lib'))

from kcore_dump import KcoreReader
from btf2json import parse_btf

KCORE    = '/proc/kcore'
KALLSYMS = '/proc/kallsyms'
BTF      = '/sys/kernel/btf/vmlinux'

# ELF e_machine values -> Ghidra processor strings
GHIDRA_PROCESSORS: dict[int, str] = {
    62:  'x86:LE:64:default',
    183: 'AARCH64:LE:64:v8A',
}

# name -> (r, w, x)
SECTION_PERMS: dict[str, tuple[bool, bool, bool]] = {
    'text':   (True,  False, True),
    'rodata': (True,  False, False),
    'init':   (True,  False, True),
    'data':   (True,  True,  False),
    'bss':    (True,  True,  False),
}

SECTIONS = [
    ('text',   ['_text', '_stext'],   ['_etext']),
    ('rodata', ['__start_rodata'],    ['__end_rodata']),
    ('init',   ['__init_begin'],      ['__init_end']),
    ('data',   ['_sdata', '__sdata'], ['_edata', '__edata']),
    ('bss',    ['__bss_start'],       ['__bss_stop']),
]



def parse_kallsyms(path: str) -> dict[str, int]:
    syms: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr, name = parts[0], parts[2]
            syms[name] = int(addr, 16)
    return syms


def btf_member_offset(btf_data: dict, type_name: str, field: str) -> int:
    """Return byte offset of field within the named struct/union."""
    t = next(t for t in btf_data['types'] if t['name'] == type_name)
    m = next(m for m in t['members'] if m['name'] == field)
    return m['bit_offset'] // 8


def btf_sizeof(btf_data: dict, type_name: str) -> int:
    t = next(t for t in btf_data['types'] if t['name'] == type_name)
    return t['size']


def btf_enum_value(btf_data: dict, enum_name: str, value_name: str) -> int:
    t = next(t for t in btf_data['types'] if t['name'] == enum_name)
    return next(v['val'] for v in t['values'] if v['name'] == value_name)


def _mem_type_perms(type_name: str) -> tuple[bool, bool, bool]:
    """Derive (r, w, x) permissions from a mod_mem_type enum value name."""
    if 'TEXT' in type_name:
        return (True, False, True)
    if 'DATA' in type_name and 'RO' not in type_name:
        return (True, True, False)
    return (True, False, False)  # RODATA, RO_AFTER_INIT


def parse_modules(syms: dict[str, int], btf_data: dict, kcore: KcoreReader) \
        -> list[tuple[str, str, int, int, bool, bool, bool]]:
    """Walk the kernel module list via kcore using BTF struct layout.

    Returns a list of (mod_name, region_type, addr, size, r, w, x) for every
    non-empty module_memory region of every loaded module.
    """
    off_list     = btf_member_offset(btf_data, 'module', 'list')
    off_name     = btf_member_offset(btf_data, 'module', 'name')
    off_mem      = btf_member_offset(btf_data, 'module', 'mem')
    off_mem_base = btf_member_offset(btf_data, 'module_memory', 'base')
    off_mem_size = btf_member_offset(btf_data, 'module_memory', 'size')
    sizeof_mem   = btf_sizeof(btf_data, 'module_memory')

    # Build ordered list of (index, type_name) for all valid mod_mem_type values.
    mem_types = next(t for t in btf_data['types']
                     if t['name'] == 'mod_mem_type')
    num_types = next(v['val'] for v in mem_types['values']
                     if v['name'] == 'MOD_MEM_NUM_TYPES')
    mem_type_names = {v['val']: v['name'] for v in mem_types['values']
                      if 0 <= v['val'] < num_types}

    modules_head = syms['modules']
    result = []
    next_ptr = kcore.u64(modules_head)
    while next_ptr != modules_head:
        mod = next_ptr - off_list
        mod_name = kcore.read(mod + off_name, 56).split(b'\x00')[0].decode()
        for idx, type_name in sorted(mem_type_names.items()):
            off = off_mem + idx * sizeof_mem
            base = kcore.u64(mod + off + off_mem_base)
            size = kcore.u32(mod + off + off_mem_size)
            if base != 0 and size != 0:
                r, w, x = _mem_type_perms(type_name)
                result.append((mod_name, type_name, base, size, r, w, x))
        next_ptr = kcore.u64(next_ptr)
    return result


def resolve_range(syms: dict[str, int], start_candidates: list[str], end_candidates: list[str]) -> tuple[int, int]:
    start = next((syms[s] for s in start_candidates if s in syms), None)
    end   = next((syms[s] for s in end_candidates   if s in syms), None)
    if start is None:
        raise ValueError(f'None of {start_candidates} found in kallsyms')
    if end is None:
        raise ValueError(f'None of {end_candidates} found in kallsyms')
    return start, end


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Dump kernel text and data sections from /proc/kcore using /proc/kallsyms')
    parser.add_argument('outdir', nargs='?', default='./kdump/', help='Output directory')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print('Parsing /proc/kallsyms...')
    syms = parse_kallsyms(KALLSYMS)

    manifest_sections = []

    with KcoreReader(KCORE) as kcore:
        e_machine = kcore.e_machine
        arch = GHIDRA_PROCESSORS.get(e_machine)
        if arch is None:
            raise ValueError(f'Unsupported e_machine {e_machine:#x}')
        print(f'Detected arch: {arch}')

        for name, start_cands, end_cands in SECTIONS:
            try:
                start, end = resolve_range(syms, start_cands, end_cands)
            except ValueError as e:
                print(f'Skipping {name}: {e}')
                continue

            length = end - start
            out_path = outdir / f'kernel_{name}.bin'
            print(f'Dumping {name}: {start:#x}-{end:#x} ({length:#x} bytes) -> {out_path}')
            kcore.dump(start, length, str(out_path))

            r, w, x = SECTION_PERMS[name]
            manifest_sections.append({
                'name': name,
                'file': str(out_path.resolve()),
                'addr': start,
                'size': length,
                'r': r, 'w': w, 'x': x,
            })

        btf_snapshot = outdir / 'vmlinux.btf'
        shutil.copy2(BTF, btf_snapshot)
        print(f'Saved BTF snapshot to {btf_snapshot}')

        btf_json_path = outdir / 'vmlinux.btf.json'
        print(f'Parsing BTF -> {btf_json_path}...')
        btf_data = parse_btf(btf_snapshot.read_bytes())
        btf_json_path.write_text(json.dumps(btf_data, indent='\t'))
        print(f'Saved BTF JSON ({len(btf_data["types"])} types) to {btf_json_path}')

        modules_dir = outdir / 'modules'
        modules_dir.mkdir(exist_ok=True)
        manifest_modules = []

        print('Walking kernel module list...')
        for mod_name, region_type, addr, size, r, w, x in parse_modules(syms, btf_data, kcore):
            out_path = modules_dir / f'{mod_name}.{region_type}.bin'
            print(f'  Dumping {mod_name} {region_type}: {addr:#x} ({size:#x} bytes) -> {out_path}')
            try:
                kcore.dump(addr, size, str(out_path))
                manifest_modules.append({
                    'name':        f'{mod_name}.{region_type}',
                    'file':        str(out_path.resolve()),
                    'addr':        addr,
                    'size':        size,
                    'r': r, 'w': w, 'x': x,
                })
            except Exception as e:
                print(f'  Skipping {mod_name} {region_type}: {str(e).splitlines()[0]}')

        vermagic = None
        if 'vermagic' in syms:
            raw = kcore.read(syms['vermagic'], 256)
            vermagic = raw.split(b'\x00')[0].decode()
            print(f'vermagic: {vermagic}')
        else:
            print('vermagic symbol not found in kallsyms')

    kallsyms_snapshot = outdir / 'kallsyms'
    shutil.copy2(KALLSYMS, kallsyms_snapshot)
    print(f'Saved kallsyms snapshot to {kallsyms_snapshot}')

    manifest = {
        'arch':     arch,
        'vermagic': vermagic,
        'sections': manifest_sections,
        'modules':  manifest_modules,
        'kallsyms': str(kallsyms_snapshot.resolve()),
        'btf':      str(btf_snapshot.resolve()),
        'btf_json': str(btf_json_path.resolve()),
    }
    manifest_path = outdir / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f'Wrote manifest to {manifest_path}')


if __name__ == '__main__':
    main()
