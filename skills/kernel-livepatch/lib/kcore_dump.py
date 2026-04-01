"""Dump an address range from /proc/kcore to a binary file."""

import argparse
import struct
from collections.abc import Iterator
from typing import BinaryIO

ELF64_EHDR = struct.Struct('<4sBBBBBxxxxxxx HHIQQQIHHHHHH')
ELF64_PHDR = struct.Struct('<IIQQQQQQ')
PT_LOAD = 1


def parse_elf_header(f: BinaryIO) -> tuple[int, int, int, int]:
    f.seek(0)
    fields = ELF64_EHDR.unpack(f.read(ELF64_EHDR.size))
    magic, e_class = fields[0], fields[1]
    if magic != b'\x7fELF':
        raise ValueError('Not an ELF file')
    if e_class != 2:
        raise ValueError(f'Expected ELF64 (class=2), got {e_class}')
    return fields[7], fields[10], fields[14], fields[15]  # e_machine, e_phoff, e_phentsize, e_phnum


def iter_phdrs(f: BinaryIO, e_phoff: int, e_phentsize: int, e_phnum: int) -> Iterator[tuple[int, int, int, int]]:
    for i in range(e_phnum):
        f.seek(e_phoff + i * e_phentsize)
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = ELF64_PHDR.unpack(f.read(ELF64_PHDR.size))
        yield p_type, p_offset, p_vaddr, p_filesz


class KcoreReader:
    """Open /proc/kcore once and support efficient repeated virtual-address reads."""

    def __init__(self, path: str):
        self._f = open(path, 'rb')
        self.e_machine, e_phoff, e_phentsize, e_phnum = parse_elf_header(self._f)
        self._segments = [
            (p_vaddr, p_vaddr + p_filesz, p_offset)
            for p_type, p_offset, p_vaddr, p_filesz
            in iter_phdrs(self._f, e_phoff, e_phentsize, e_phnum)
            if p_type == PT_LOAD
        ]

    def read(self, addr: int, length: int) -> bytes:
        for vstart, vend, foffset in self._segments:
            if vstart <= addr and addr + length <= vend:
                self._f.seek(foffset + (addr - vstart))
                return self._f.read(length)
        raise ValueError(f'Address {addr:#x} not found in kcore')

    def u32(self, addr: int) -> int:
        return struct.unpack_from('<I', self.read(addr, 4))[0]

    def u64(self, addr: int) -> int:
        return struct.unpack_from('<Q', self.read(addr, 8))[0]

    def close(self) -> None:
        self._f.close()

    def dump(self, addr: int, length: int, out_path: str) -> None:
        data = self.read(addr, length)
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f'Wrote {length} bytes to {out_path}')

    def __enter__(self) -> 'KcoreReader':
        return self

    def __exit__(self, *_) -> None:
        self.close()


def dump(kcore_path: str, start_addr: int, length: int, out_path: str) -> None:
    with open(kcore_path, 'rb') as kf:
        _, e_phoff, e_phentsize, e_phnum = parse_elf_header(kf)

        file_offset = next(
            (p_offset + (start_addr - p_vaddr)
             for p_type, p_offset, p_vaddr, p_filesz in iter_phdrs(kf, e_phoff, e_phentsize, e_phnum)
             if p_type == PT_LOAD and p_vaddr <= start_addr and start_addr + length <= p_vaddr + p_filesz),
            None,
        )

        if file_offset is None:
            segs = [(p_vaddr, p_vaddr + p_filesz)
                    for p_type, _, p_vaddr, p_filesz in iter_phdrs(kf, e_phoff, e_phentsize, e_phnum)
                    if p_type == PT_LOAD]
            seg_list = '\n'.join(f'  {s:#x}-{e:#x}' for s, e in segs)
            raise ValueError(
                f'Address range {start_addr:#x}-{start_addr + length:#x} not found in any PT_LOAD segment.\n'
                f'Available PT_LOAD segments:\n{seg_list}')

        kf.seek(file_offset)
        data = kf.read(length)

    if len(data) != length:
        raise IOError(f'Short read: got {len(data)} bytes, expected {length}')

    with open(out_path, 'wb') as out:
        out.write(data)

    print(f'Wrote {length} bytes to {out_path}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Dump an address range from /proc/kcore to a .bin file')
    parser.add_argument('start', help='Start virtual address (hex, e.g. 0xffffffff81000000)')
    parser.add_argument('length', help='Number of bytes to dump (hex or decimal)')
    parser.add_argument('output', help='Output .bin file')
    parser.add_argument('--kcore', default='/proc/kcore',
                        help='Path to kcore (default: /proc/kcore)')
    args = parser.parse_args()

    dump(args.kcore, int(args.start, 0), int(args.length, 0), args.output)


if __name__ == '__main__':
    main()
