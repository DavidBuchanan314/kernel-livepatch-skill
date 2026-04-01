# -*- coding: utf-8 -*-
# Ghidra script: print disassembly and annotated
# decompilation (with instruction addresses) of a named function.
#
# Usage (headless):
#   -postScript ghidra_print_func.py <function_name> [output_file]
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
    raise SystemExit('Usage: ghidra_print_func.py <function_name|address> [output_file] [length]')

func_name = args[0]
out = open(args[1], 'w') if len(args) > 1 else None
disasm_length = int(args[2], 0) if len(args) > 2 else None

def emit(s=''):
    if out:
        out.write(s + '\n')
    else:
        print(s)

listing = currentProgram.getListing()
ref_mgr      = currentProgram.getReferenceManager()
symbol_table = currentProgram.getSymbolTable()

def _disasm_range(start_addr, end_addr):
    """Disassemble and print instructions in an address range."""
    from ghidra.program.model.address import AddressSet
    addr_set = AddressSet(start_addr, end_addr)
    runCommand(DisassembleCommand(addr_set, None, True))

    emit('')
    emit('=== DISASSEMBLY: %s-%s ===' % (start_addr, end_addr))
    for cu in listing.getCodeUnits(addr_set, True):
        raw = ''.join('%02x' % (b & 0xff) for b in cu.getBytes())
        syms = []
        for ref in ref_mgr.getReferencesFrom(cu.getAddress()):
            sym = symbol_table.getPrimarySymbol(ref.getToAddress())
            if sym is not None:
                syms.append(sym.getName())
        suffix = ('  ; ' + ', '.join(syms)) if syms else ''
        emit('%s  %-8s  %s%s' % (cu.getAddress(), raw, cu, suffix))

if disasm_length is not None:
    # Address + length disassembly-only mode
    addr_str = func_name
    if addr_str.startswith('0x') or addr_str.startswith('0X'):
        addr_str = addr_str[2:]
    start_addr = toAddr(addr_str)
    end_addr = start_addr.add(disasm_length - 1)
    _disasm_range(start_addr, end_addr)
else:
    # Named function mode: decompile + disassemble
    funcs = list(getGlobalFunctions(func_name))
    if not funcs:
        emit('ERROR: function %r not found.' % func_name)
        raise SystemExit(1)
    if len(funcs) > 1:
        emit('WARNING: %d functions named %r; using first.' % (len(funcs), func_name))

    func = funcs[0]

    # -------------------------------------------------------------------
    # Decompilation with address annotations
    # -------------------------------------------------------------------

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
                emit('%-80s  /* %s */' % (line, addr))
            else:
                emit(line)

    emit('')
    emit('=== DECOMPILATION: %s ===' % func.getName())
    decompiler = DecompInterface()
    try:
        decompiler.openProgram(currentProgram)
        result = decompiler.decompileFunction(func, 60, monitor)
        if result.decompileCompleted():
            _print_decomp_annotated(result.getCCodeMarkup(), result.getDecompiledFunction().getC())
        else:
            emit('ERROR: decompilation failed: %s' % result.getErrorMessage())
    finally:
        decompiler.dispose()

    # -------------------------------------------------------------------
    # Disassembly
    # -------------------------------------------------------------------
    runCommand(DisassembleCommand(func.getBody(), None, True))
    runCommand(CreateFunctionCmd(func.getName(), func.getEntryPoint(), None, SourceType.IMPORTED, True, True))
    func = getGlobalFunctions(func_name)[0]

    emit('')
    emit('=== DISASSEMBLY: %s @ %s ===' % (func.getName(), func.getEntryPoint()))
    for cu in listing.getCodeUnits(func.getBody(), True):
        raw = ''.join('%02x' % (b & 0xff) for b in cu.getBytes())
        syms = []
        for ref in ref_mgr.getReferencesFrom(cu.getAddress()):
            sym = symbol_table.getPrimarySymbol(ref.getToAddress())
            if sym is not None:
                syms.append(sym.getName())
        suffix = ('  ; ' + ', '.join(syms)) if syms else ''
        emit('%s  %-8s  %s%s' % (cu.getAddress(), raw, cu, suffix))

if out:
    out.close()
