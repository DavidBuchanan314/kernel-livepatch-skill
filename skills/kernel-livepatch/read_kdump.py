"""Read raw memory from a kdump manifest and write it to stdout."""

import argparse
import json
import sys


def hexdump(data: bytes, base_addr: int) -> None:
    """Print data in hexdump -C format with correct virtual addresses."""
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hex_parts = []
        for i in range(16):
            if i < len(chunk):
                hex_parts.append(f'{chunk[i]:02x}')
            else:
                hex_parts.append('  ')
        left = ' '.join(hex_parts[:8])
        right = ' '.join(hex_parts[8:])
        ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        print(f'{base_addr + off:016x}  {left}  {right}  |{ascii_part}|')
    print(f'{base_addr + len(data):016x}')


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Read raw memory data from a kdump manifest')
    parser.add_argument('manifest', nargs='?', default='./kdump/manifest.json',
                        help='Path to manifest.json (default: ./kdump/manifest.json)')
    parser.add_argument('addr', help='Virtual address to read (hex or decimal)')
    parser.add_argument('length', help='Number of bytes to read (hex or decimal)')
    parser.add_argument('-x', '--hexdump', action='store_true',
                        help='Output as hexdump -C format with virtual addresses')
    args = parser.parse_args()

    addr = int(args.addr, 0)
    length = int(args.length, 0)

    with open(args.manifest) as f:
        manifest = json.load(f)

    # Build a list of all regions (sections + modules)
    regions = manifest.get('sections', []) + manifest.get('modules', [])

    for region in regions:
        r_addr = region['addr']
        r_size = region['size']
        if r_addr <= addr and addr + length <= r_addr + r_size:
            offset = addr - r_addr
            with open(region['file'], 'rb') as bf:
                bf.seek(offset)
                data = bf.read(length)
            if len(data) != length:
                print(f'Short read: got {len(data)} bytes, expected {length}',
                      file=sys.stderr)
                sys.exit(1)
            if args.hexdump:
                hexdump(data, addr)
            else:
                sys.stdout.buffer.write(data)
            return

    # No matching region found
    print(f'Address range {addr:#x}-{addr + length:#x} not found in any region.',
          file=sys.stderr)
    print('Available regions:', file=sys.stderr)
    for r in regions:
        end = r['addr'] + r['size']
        print(f'  {r["name"]}: {r["addr"]:#x}-{end:#x}', file=sys.stderr)
    sys.exit(1)


if __name__ == '__main__':
    main()
