"""Load kernel sections from a kdump manifest into a new Ghidra project (run as non-root)."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'lib'))

from ghidra_run import ghidra_run


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Import kernel dump sections into a Ghidra project')
    parser.add_argument('manifest',     nargs='?', default='./kdump/manifest.json',
                        help='manifest.json written by kdump_sections.py')
    parser.add_argument('project_dir',  nargs='?', default='./ghidra',
                        help='Ghidra project directory')
    parser.add_argument('project_name', nargs='?', default='kernel',
                        help='Ghidra project name')
    parser.add_argument('--ghidra',     default='',
                        help='Path to GHIDRA_HOME (or set $GHIDRA_HOME); omit to use flatpak')
    parser.add_argument('--analyze', action='store_true',
                        help='Run Ghidra auto-analysis after import (very slow!!!)')
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    with open(manifest_path) as f:
        manifest = json.load(f)

    sections = manifest['sections']
    if not sections:
        raise SystemExit('No sections in manifest')

    first = sections[0]
    add_sections_script = Path(__file__).parent.resolve() / 'ghidra-scripts' / 'ghidra_add_sections.py'

    headless_args = [
        '-import',          first['file'],
        '-loader',          'BinaryLoader',
        '-loader-baseAddr', hex(first['addr']),
        '-processor',       manifest['arch'],
        '-preScript',       add_sections_script.name, str(manifest_path),
        '-scriptPath',      str(add_sections_script.parent),
        '-overwrite',
    ]
    if not args.analyze:
        headless_args.append('-noanalysis')

    ghidra_run(args.project_dir, args.project_name, headless_args, args.ghidra)


if __name__ == '__main__':
    main()
