"""Decompile and disassemble a named kernel function from a Ghidra project (run as non-root)."""

import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'lib'))

from ghidra_run import ghidra_run


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Print decompilation and disassembly of a kernel function')
    parser.add_argument('function',     help='Function name (or address when using --disasm)')
    parser.add_argument('project_dir',  nargs='?', default='./ghidra',
                        help='Ghidra project directory')
    parser.add_argument('project_name', nargs='?', default='kernel',
                        help='Ghidra project name')
    parser.add_argument('--ghidra',     default='',
                        help='Path to GHIDRA_HOME (or set $GHIDRA_HOME); omit to use flatpak')
    parser.add_argument('--disasm',     metavar='LENGTH',
                        help='Disassemble only (no decompilation) at address FUNCTION for LENGTH bytes')
    args = parser.parse_args()

    script = Path(__file__).parent.resolve() / 'ghidra-scripts' / 'ghidra_print_func.py'

    # flatpak ghidra doesn't like writing to /tmp/
    with tempfile.NamedTemporaryFile(dir=Path.home(), suffix='.txt', delete=False) as f:
        outfile = f.name

    script_args = [args.function, outfile]
    if args.disasm is not None:
        script_args.append(args.disasm)

    try:
        ghidra_run(args.project_dir, args.project_name, [
            '-noanalysis',
            '-process',
            '-postScript', script.name, *script_args,
            '-scriptPath', str(script.parent),
        ], args.ghidra, quiet=True)
    finally:
        out = Path(outfile)
        if out.exists():
            print(out.read_text(), end='')
            out.unlink()


if __name__ == '__main__':
    main()
