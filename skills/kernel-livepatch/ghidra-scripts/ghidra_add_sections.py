# -*- coding: utf-8 -*-
# Ghidra headless pre-script: loads kernel sections, imports kallsyms symbols,
# and applies BTF type information (structs, enums, typedefs, function sigs).
#
# Runs inside Ghidra's Jython 2.7 interpreter - keep compatible.
#
# @category Kernel

import json
from java.io import FileInputStream
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

manifest_path = getScriptArgs()[0]

with open(manifest_path) as f:
    manifest = json.load(f)

sections     = manifest['sections']
memory       = currentProgram.getMemory()
space        = currentProgram.getAddressFactory().getDefaultAddressSpace()
symbol_table = currentProgram.getSymbolTable()
listing      = currentProgram.getListing()


def to_addr(addr_int):
    return space.getAddress(hex(addr_int).rstrip('L'))


# ---------------------------------------------------------------------------
# Load memory sections
# ---------------------------------------------------------------------------

first       = sections[0]
first_block = memory.getBlock(to_addr(first['addr']))
if first_block is not None:
    first_block.setName(first['name'])
    first_block.setRead(first['r'])
    first_block.setWrite(first['w'])
    first_block.setExecute(first['x'])

for section in sections[1:]:
    addr  = to_addr(section['addr'])
    fis   = FileInputStream(section['file'])
    block = memory.createInitializedBlock(section['name'], addr, fis, section['size'], None, False)
    block.setRead(section['r'])
    block.setWrite(section['w'])
    block.setExecute(section['x'])

print('Sections loaded.')

# ---------------------------------------------------------------------------
# Load modules
# ---------------------------------------------------------------------------

modules = manifest.get('modules', [])
n_mods = 0
for mod in modules:
    try:
        addr  = to_addr(mod['addr'])
        fis   = FileInputStream(mod['file'])
        block = memory.createInitializedBlock(mod['name'], addr, fis, mod['size'], None, False)
        block.setRead(mod['r'])
        block.setWrite(mod['w'])
        block.setExecute(mod['x'])
        n_mods += 1
    except Exception as e:
        print('  skipping module %s: %s' % (mod['name'], e))

print('Modules loaded: %d / %d.' % (n_mods, len(modules)))

# ---------------------------------------------------------------------------
# Import kallsyms symbols
# ---------------------------------------------------------------------------

ranges = [(s['addr'], s['addr'] + s['size']) for s in sections]
ranges += [(m['addr'], m['addr'] + m['size']) for m in modules]

def in_loaded_range(addr_int):
    for start, end in ranges:
        if start <= addr_int < end:
            return True
    return False

FUNC_TYPES = set('TtWw')

kallsyms_path = manifest.get('kallsyms')
if not kallsyms_path:
    print('No kallsyms in manifest, skipping symbol import.')
else:
    with open(kallsyms_path) as f:
        all_lines = [l for l in f if len(l.split()) >= 3]

    total = len(all_lines)
    n_labels = n_funcs = n_skip = 0
    REPORT_EVERY = 10000

    for i, line in enumerate(all_lines):
        parts    = line.split()
        addr_int = int(parts[0], 16)
        sym_type = parts[1]
        name     = parts[2]

        if i % REPORT_EVERY == 0:
            print('  %d / %d symbols...' % (i, total))

        if addr_int == 0 or not in_loaded_range(addr_int):
            n_skip += 1
            continue
        name = ''.join(c if 0x20 <= ord(c) < 0x7f else '_' for c in name)

        addr = to_addr(addr_int)
        try:
            if sym_type in FUNC_TYPES:
                func = listing.getFunctionAt(addr)
                if func is None:
                    listing.createFunction(name, addr, AddressSet(addr, addr), SourceType.IMPORTED)
                else:
                    func.setName(name, SourceType.IMPORTED)
                n_funcs += 1
            else:
                symbol_table.createLabel(addr, name, SourceType.IMPORTED)
                n_labels += 1
        except Exception as e:
            print('  symbol %s: %s' % (name, e))

    print('Symbols: %d functions, %d labels, %d skipped.' % (n_funcs, n_labels, n_skip))

# ---------------------------------------------------------------------------
# Import BTF types
# ---------------------------------------------------------------------------

btf_json_path = manifest.get('btf_json')
if not btf_json_path:
    print('No btf_json in manifest, skipping type import.')
else:
    from ghidra.program.model.data import (
        AbstractIntegerDataType,
        ArrayDataType,
        BooleanDataType,
        CategoryPath,
        CharDataType,
        DataTypeConflictHandler,
        DoubleDataType,
        EnumDataType,
        FloatDataType,
        FunctionDefinitionDataType,
        LongDoubleDataType,
        ParameterDefinitionImpl,
        PointerDataType,
        StructureDataType,
        TypedefDataType,
        UnionDataType,
        VoidDataType,
    )
    from ghidra.program.model.listing import Function, ParameterImpl

    REPLACE       = DataTypeConflictHandler.REPLACE_HANDLER
    CAT_STRUCT    = CategoryPath('/btf/struct')
    CAT_UNION     = CategoryPath('/btf/union')
    CAT_ENUM      = CategoryPath('/btf/enum')
    CAT_TYPEDEF   = CategoryPath('/btf/typedef')
    CAT_FUNC      = CategoryPath('/btf/func')
    dtm           = currentProgram.getDataTypeManager()
    PTR_SIZE      = currentProgram.getDefaultPointerSize()

    print('Loading BTF JSON from %s ...' % btf_json_path)
    with open(btf_json_path) as _f:
        _btf_data = json.load(_f)
    # Build id -> type dict preserving declaration order.
    btf_types = {}
    for _t in _btf_data['types']:
        btf_types[_t['id']] = _t
    print('BTF: %d types.' % len(btf_types))

    _resolved         = {}   # type_id -> Ghidra DataType
    _enum_value_names = set()  # global enum value name registry

    def _add_enum_value(dt, name, value):
        final = name
        suffix = 2
        while final in _enum_value_names:
            final = '%s_%d' % (name, suffix)
            suffix += 1
        java_val = long(value)
        if java_val > 0x7FFFFFFFFFFFFFFF:
            java_val -= (1 << 64)
        try:
            dt.add(final, java_val)
            _enum_value_names.add(final)
        except Exception as e:
            print('  skipping enum value %s: %s' % (final, e))

    def _add(dt, type_id):
        """Add dt to the DTM, suffixing with type_id if the name is already taken in its category."""
        if dtm.getDataType(dt.getCategoryPath(), dt.getName()) is not None:
            dt.setName('%s_%d' % (dt.getName(), type_id))
            print('  name conflict, using %s' % dt.getName())
        return dtm.addDataType(dt, REPLACE)

    def _int_ghidra(bt):
        enc = bt['int']['encoding']
        if enc['bool']:
            return BooleanDataType.dataType
        if enc['char']:
            return CharDataType.dataType
        if enc['signed']:
            return AbstractIntegerDataType.getSignedDataType(bt['size'], dtm)
        return AbstractIntegerDataType.getUnsignedDataType(bt['size'], dtm)

    def _float_ghidra(bt):
        if bt['size'] == 4:
            return FloatDataType.dataType
        if bt['size'] == 8:
            return DoubleDataType.dataType
        return LongDoubleDataType.dataType

    def resolve(type_id):
        if type_id == 0:
            return VoidDataType.dataType
        if type_id in _resolved:
            return _resolved[type_id]
        bt = btf_types.get(type_id)
        if bt is None:
            return VoidDataType.dataType
        # Structs/unions are pre-created in pass 1 - return skeleton to break cycles.
        # Other types: set a placeholder first to break any unexpected cycle, then resolve.
        _resolved[type_id] = VoidDataType.dataType
        try:
            result = _resolve_type(bt)
        except Exception as e:
            print('  resolve type_id %d (%s): %s' % (bt['id'], bt['name'], e))
            result = VoidDataType.dataType
        _resolved[type_id] = result
        return result

    def _resolve_type(bt):
        kind = bt['kind']

        if kind == 'INT':
            return _int_ghidra(bt)

        elif kind == 'FLOAT':
            return _float_ghidra(bt)

        elif kind == 'PTR':
            return PointerDataType(resolve(bt['type_id'] or 0), PTR_SIZE, dtm)

        elif kind == 'ARRAY':
            arr = bt['array']
            elem = resolve(arr['type_id'])
            if arr['nelems'] == 0 or elem.getLength() <= 0:
                return elem
            return ArrayDataType(elem, arr['nelems'], elem.getLength(), dtm)

        elif kind in ('STRUCT', 'UNION'):
            # Already in _resolved from pass 1.
            return _resolved.get(bt['id'], VoidDataType.dataType)

        elif kind in ('ENUM', 'ENUM64'):
            name = bt['name'] or ('anon_%d' % bt['id'])
            size = min(bt['size'], 8)
            dt = EnumDataType(CAT_ENUM, name, size)
            seen_vals = set()  # skip aliased values (same int, different name) - Ghidra warns on non-unique value→name mappings
            for v in bt['values']:
                if v['val'] not in seen_vals:
                    _add_enum_value(dt, v['name'], v['val'])
                    seen_vals.add(v['val'])
            return _add(dt, bt['id'])

        elif kind == 'TYPEDEF':
            inner = resolve(bt['type_id'] or 0)
            return _add(TypedefDataType(CAT_TYPEDEF, bt['name'], inner, dtm), bt['id'])

        elif kind in ('VOLATILE', 'CONST', 'RESTRICT', 'TYPE_TAG'):
            return resolve(bt['type_id'] or 0)

        elif kind == 'FUNC_PROTO':
            name = bt['name'] or ('proto_%d' % bt['id'])
            dt = FunctionDefinitionDataType(CAT_FUNC, name)
            dt.setReturnType(resolve(bt['type_id'] or 0))
            params = []
            has_varargs = False
            for i, p in enumerate(bt['params']):
                if not p['type_id']:
                    has_varargs = True
                    continue
                params.append(ParameterDefinitionImpl(p['name'] or ('arg%d' % i), resolve(p['type_id']), ''))
            if params:
                dt.setArguments(params)
            dt.setVarArgs(has_varargs)
            return _add(dt, bt['id'])

        return VoidDataType.dataType

    REPORT_EVERY_BTF = 5000
    total_types = len(btf_types)

    def _progress(i, label):
        if i % REPORT_EVERY_BTF == 0:
            print('  %s: %d / %d...' % (label, i, total_types))

    # Pass 1: create skeleton structs and unions.
    print('BTF pass 1: creating skeletons (%d types)...' % total_types)
    for i, (type_id, bt) in enumerate(btf_types.items()):
        _progress(i, 'pass 1')
        try:
            if bt['kind'] == 'STRUCT':
                name = bt['name'] or ('anon_%d' % type_id)
                _resolved[type_id] = _add(StructureDataType(CAT_STRUCT, name, bt['size']), type_id)
            elif bt['kind'] == 'UNION':
                name = bt['name'] or ('anon_%d' % type_id)
                _resolved[type_id] = _add(UnionDataType(CAT_UNION, name), type_id)
        except Exception as e:
            print('  pass 1 type_id %d (%s): %s' % (type_id, bt['name'], e))
    print('BTF pass 1: %d skeletons created.' % len(_resolved))

    # Pass 2: fill struct/union members.
    print('BTF pass 2: filling members...')
    n_composites = 0
    for i, (type_id, bt) in enumerate(btf_types.items()):
        if bt['kind'] not in ('STRUCT', 'UNION'):
            continue
        _progress(i, 'pass 2')
        dt = _resolved.get(type_id)
        if dt is None:
            continue
        for m in bt['members']:
            if m.get('bitfield_size', 0) != 0 or m['bit_offset'] % 8 != 0:
                continue  # skip bitfields and unaligned members
            try:
                mtype = resolve(m['type_id'])
                mlen  = mtype.getLength()
                if mlen <= 0:
                    continue
                mname = m['name'] or ''
                if bt['kind'] == 'STRUCT':
                    byte_off = m['bit_offset'] // 8
                    if byte_off + mlen <= bt['size']:
                        dt.replaceAtOffset(byte_off, mtype, mlen, mname, '')
                else:
                    dt.add(mtype, mlen, mname, '')
            except Exception as e:
                print('  pass 2 %s.%s: %s' % (bt['name'], m['name'], e))
        n_composites += 1
    print('BTF pass 2: filled %d structs/unions.' % n_composites)

    # Pass 3: resolve all remaining types (typedefs, enums, etc.)
    print('BTF pass 3: resolving remaining types...')
    for i, type_id in enumerate(btf_types):
        _progress(i, 'pass 3')
        resolve(type_id)
    print('BTF pass 3: %d types resolved.' % len(_resolved))

    # Pass 4: apply function signatures.
    print('BTF pass 4: applying function signatures...')
    n_typed = 0
    for i, (type_id, bt) in enumerate(btf_types.items()):
        if bt['kind'] != 'FUNC' or not bt['name']:
            continue
        _progress(i, 'pass 4')
        proto = btf_types.get(bt['type_id'])
        if proto is None or proto['kind'] != 'FUNC_PROTO':
            continue
        for sym in list(symbol_table.getSymbols(bt['name'])):
            func = listing.getFunctionAt(sym.getAddress())
            if func is None:
                continue
            try:
                return_type = resolve(proto['type_id'] or 0)
                func.setReturnType(return_type, SourceType.IMPORTED)
                params = []
                has_varargs = False
                for i, p in enumerate(proto['params']):
                    if not p['type_id']:
                        has_varargs = True
                        continue
                    params.append(ParameterImpl(
                        p['name'] or ('arg%d' % i), resolve(p['type_id']), currentProgram))
                if params:
                    func.updateFunction(
                        None, None, params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        True, SourceType.IMPORTED)
                n_typed += 1
            except Exception as e:
                print('  pass 4 %s: %s' % (bt['name'], e))
    print('BTF pass 4: typed %d functions.' % n_typed)

print('Done: %s' % currentProgram.getName())
