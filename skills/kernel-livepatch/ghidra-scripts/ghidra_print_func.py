# -*- coding: utf-8 -*-
# Ghidra script: print disassembly and annotated
# decompilation (with instruction addresses) of a named function.
#
# Usage (headless):
#   -postScript ghidra_print_func.py <function_name>
#
# Runs inside Ghidra's Jython 2.7 interpreter - keep compatible.
#
# @category Kernel

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import ClangBreak, DecompInterface
from ghidra.program.model.symbol import SourceType

args = getScriptArgs()
if not args:
    print('Usage: ghidra_print_func.py <function_name>')
    raise SystemExit(1)

func_name = args[0]

# Look up function by name.
funcs = list(getGlobalFunctions(func_name))
if not funcs:
    print('ERROR: function %r not found.' % func_name)
    raise SystemExit(1)
if len(funcs) > 1:
    print('WARNING: %d functions named %r; using first.' % (len(funcs), func_name))

func = funcs[0]
listing = currentProgram.getListing()

# ---------------------------------------------------------------------------
# Decompilation with address annotations
# ---------------------------------------------------------------------------

def _iter_tokens(node):
    """Recursively yield all leaf ClangTokens from a ClangTokenGroup tree."""
    for i in xrange(node.numChildren()):
        child = node.Child(i)
        if child.numChildren() > 0:
            for t in _iter_tokens(child):
                yield t
        else:
            yield child

def _build_line_addr_map(markup):
    """Return a dict mapping 1-based line number -> first instruction address on that line."""
    line_map = {}
    line_num = 1
    for token in _iter_tokens(markup):
        addr = token.getMinAddress()
        if addr is not None and line_num not in line_map:
            line_map[line_num] = addr
        if isinstance(token, ClangBreak):
            line_num += 1
    return line_map

def _print_decomp_annotated(markup, c_code):
    """Print decompiled C (from getC()) with /* address */ comments appended per line."""
    line_map = _build_line_addr_map(markup)
    for i, line in enumerate(c_code.split('\n')):
        addr = line_map.get(i + 1)
        if addr is not None:
            print('%-80s  /* %s */' % (line, addr))
        else:
            print(line)

print('')
print('=== DECOMPILATION: %s ===' % func.getName())
decompiler = DecompInterface()
try:
    decompiler.openProgram(currentProgram)
    result = decompiler.decompileFunction(func, 60, monitor)
    if result.decompileCompleted():
        _print_decomp_annotated(result.getCCodeMarkup(), result.getDecompiledFunction().getC())
    else:
        print('ERROR: decompilation failed: %s' % result.getErrorMessage())
finally:
    decompiler.dispose()

# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------
if listing.getInstructionAt(func.getEntryPoint()) is None:
    print('Disassembling %s...' % func_name)
    runCommand(DisassembleCommand(func.getBody(), None, True))
    runCommand(CreateFunctionCmd(func.getName(), func.getEntryPoint(), None, SourceType.IMPORTED, True, True))
    func = getGlobalFunctions(func_name)[0]

ref_mgr      = currentProgram.getReferenceManager()
symbol_table = currentProgram.getSymbolTable()

print('')
print('=== DISASSEMBLY: %s @ %s ===' % (func.getName(), func.getEntryPoint()))
for cu in listing.getCodeUnits(func.getBody(), True):
    raw = ''.join('%02x' % (b & 0xff) for b in cu.getBytes())
    syms = []
    for ref in ref_mgr.getReferencesFrom(cu.getAddress()):
        sym = symbol_table.getPrimarySymbol(ref.getToAddress())
        if sym is not None:
            syms.append(sym.getName())
    suffix = ('  ; ' + ', '.join(syms)) if syms else ''
    print('%s  %-8s  %s%s' % (cu.getAddress(), raw, cu, suffix))
