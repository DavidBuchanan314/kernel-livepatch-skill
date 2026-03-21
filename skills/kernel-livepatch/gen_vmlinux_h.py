#!/usr/bin/env python3
"""Generate vmlinux.h from BTF data (like bpftool gen vmlinux)."""

import json
import os
import sys
import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent / 'lib'))

import btf
from btf import (
    Btf, BtfKind, BtfType,
    BtfInt, BtfFloat, BtfPtr, BtfArray,
    BtfStruct, BtfUnion, BtfEnum, BtfEnum64,
    BtfFwd, BtfTypedef, BtfModifier, BtfFunc, BtfFuncProto,
    BtfVar, BtfDatasec, BtfDeclTag, BtfMember, BtfParam,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_c_ident(name: str) -> bool:
    return bool(name) and bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name))


def _sanitize(name: str) -> str:
    """Replace non-ident chars (e.g. dots) with underscores."""
    if not name:
        return name
    s = re.sub(r'[^A-Za-z0-9_]', '_', name)
    if s and s[0].isdigit():
        s = '_' + s
    return s


# ---------------------------------------------------------------------------
# Type name emission  (used in declarations and member types)
# ---------------------------------------------------------------------------

class Generator:
    def __init__(self, b: Btf, kallsyms: dict[str, int] | None = None, vermagic: str | None = None):
        self.b = b
        self.kallsyms = kallsyms or {}
        self.vermagic = vermagic
        self._emitted: set[int] = set()          # type_ids started/finished processing
        self._typedef_output: set[int] = set()  # typedef type_ids actually written out
        self._emitted_names: set[str] = set()   # "struct foo", "enum bar", enumerator names emitted
        self._typedef_names: set[str] = set()   # typedef names emitted (to skip conflicting redefs)
        self._fwd_emitted: set[str] = set()     # "struct foo" forward decls emitted
        self._tag_renames: dict[int, str] = {}  # type_id -> renamed name for cross-tag conflicts
        self._emitted_sizes: dict[str, int] = {} # "struct foo" -> emitted size (for deduped types)
        self._out: list[str] = []

    # ------------------------------------------------------------------
    # C type reference (for use inside a declaration, not top-level def)
    # ------------------------------------------------------------------

    def _type_ref(self, type_id: int, depth: int = 0) -> str:
        """Return a C type string for referencing type_id."""
        if type_id == 0:
            return 'void'
        if depth > 32:
            return f'/* recursive */ void *'
        t = self.b.get_type(type_id)
        if t is None:
            return 'void'

        if isinstance(t, BtfInt):
            return t.name or 'int'
        if isinstance(t, BtfFloat):
            return t.name or 'float'
        if isinstance(t, BtfPtr):
            pt = self.b.get_type(t.pointee_type_id)
            if isinstance(pt, (BtfStruct, BtfUnion)) and not pt.name:
                return 'void *'  # pointer to anonymous struct/union — no expressible C type
            inner = self._type_ref(t.pointee_type_id, depth + 1)
            return f'{inner} *'
        if isinstance(t, BtfArray):
            # Arrays are handled specially at the member level
            inner = self._type_ref(t.elem_type_id, depth + 1)
            return f'{inner} [{t.nelems}]' if t.nelems else f'{inner} []'
        if isinstance(t, BtfTypedef):
            return _sanitize(t.name)
        if isinstance(t, BtfModifier):
            quals, base_tid = self._strip_modifiers(type_id)
            inner = self._type_ref(base_tid, depth + 1)
            if not quals:
                return inner
            quals_str = ' '.join(quals)
            # If base is a pointer, qualifiers go after * (they qualify the ptr)
            base_t = self.b.get_type(base_tid)
            if isinstance(base_t, BtfPtr):
                return f'{inner} {quals_str}'
            return f'{quals_str} {inner}'
        if isinstance(t, (BtfStruct, BtfUnion)):
            kw = 'struct' if isinstance(t, BtfStruct) else 'union'
            name = self._tag_renames.get(type_id, _sanitize(t.name))
            return f'{kw} {name}' if name else kw
        if isinstance(t, (BtfEnum, BtfEnum64)):
            name = self._tag_renames.get(type_id, _sanitize(t.name))
            return f'enum {name}' if name else 'enum'
        if isinstance(t, BtfFwd):
            return f'{t.fwd_kind} {_sanitize(t.name)}'
        if isinstance(t, BtfFuncProto):
            ret = self._type_ref(t.return_type_id, depth + 1)
            params = self._proto_params_str(t, depth + 1)
            return f'{ret} (*)({params})'
        return t.name or f'/* kind={t.kind.name} */ void'

    def _param_str(self, p: BtfParam, depth: int) -> str:
        name = _sanitize(p.name) if p.name else ''
        _, base_tid = self._strip_modifiers(p.type_id)
        base_t = self.b.get_type(base_tid)
        if isinstance(base_t, BtfArray):
            inner = self._type_ref(base_t.elem_type_id, depth + 1)
            dims = f'[{base_t.nelems}]' if base_t.nelems else '[0]'
            return f'{inner} {name}{dims}'.strip()
        # Function pointer param (handles ptr → [mods →] funcproto)
        fp = self._funcptr_parts(p.type_id)
        if fp is not None:
            ret, params, fp_quals = fp
            qual_mid = ' '.join(fp_quals) + ' ' if fp_quals else ''
            return f'{ret} (*{qual_mid}{name})({params})'
        # Pointer(s)-to-array param: type ([quals] stars name)[dims]
        arr_parts = self._ptr_to_array_parts(p.type_id)
        if arr_parts is not None:
            inner, stars, dims, quals = arr_parts
            qual_sfx = ' ' + ' '.join(quals) if quals else ''
            return f'{inner} ({stars}{qual_sfx} {name}){dims}'.strip()
        ref = self._type_ref(p.type_id, depth)
        return f'{ref} {name}'.strip()

    # ------------------------------------------------------------------
    # Member declaration line
    # ------------------------------------------------------------------

    def _strip_modifiers(self, type_id: int) -> tuple[list[str], int]:
        """Return (list_of_qualifiers, underlying_type_id) after stripping modifiers."""
        quals = []
        seen = set()
        while type_id not in seen:
            seen.add(type_id)
            t = self.b.get_type(type_id)
            if not isinstance(t, BtfModifier):
                break
            q = {BtfKind.CONST: 'const', BtfKind.VOLATILE: 'volatile',
                 BtfKind.RESTRICT: 'restrict'}.get(t.kind)
            if q and q not in quals:
                quals.append(q)
            type_id = t.modified_type_id
        return quals, type_id

    def _ptr_to_array_parts(self, type_id: int) -> 'tuple[str, str, str, list[str]] | None':
        """If type_id is [quals] ptr+ → [quals] array, return (elem_ref, stars, dims, outer_quals)."""
        outer_quals, tid = self._strip_modifiers(type_id)
        stars = 0
        while True:
            t = self.b.get_type(tid)
            if isinstance(t, BtfPtr):
                stars += 1
                _, tid = self._strip_modifiers(t.pointee_type_id)
            else:
                break
        if stars == 0:
            return None
        t = self.b.get_type(tid)
        if not isinstance(t, BtfArray):
            return None
        inner = self._type_ref(t.elem_type_id)
        dims = f'[{t.nelems}]' if t.nelems else '[0]'
        return inner, '*' * stars, dims, outer_quals

    def _funcptr_parts(self, type_id: int) -> 'tuple[str, str, list[str]] | None':
        """If type_id (possibly through ptr/modifiers) is a func pointer,
        return (ret_str, params_str, qualifier_list). Else None."""
        quals, tid = self._strip_modifiers(type_id)
        t = self.b.get_type(tid)
        proto = None
        if isinstance(t, BtfFuncProto):
            proto = t
        elif isinstance(t, BtfPtr):
            # Strip modifiers from pointee (handles ptr → volatile → funcproto)
            inner_quals, inner_tid = self._strip_modifiers(t.pointee_type_id)
            inner_t = self.b.get_type(inner_tid)
            if isinstance(inner_t, BtfFuncProto):
                proto = inner_t
                quals = inner_quals + quals
            elif isinstance(inner_t, BtfPtr):
                # ptr → [mods →] ptr → [mods →] funcproto
                inner2_quals, inner2_tid = self._strip_modifiers(inner_t.pointee_type_id)
                inner2_t = self.b.get_type(inner2_tid)
                if isinstance(inner2_t, BtfFuncProto):
                    proto = inner2_t
                    quals = ['*'] + inner2_quals + inner_quals + quals
        if proto is None:
            return None
        ret = self._type_ref(proto.return_type_id)
        params = self._proto_params_str(proto)
        return ret, params, quals

    def _proto_params_str(self, proto: BtfFuncProto, depth: int = 0) -> str:
        """Render parameter list, filtering void-typed params that aren't the sole param."""
        params = proto.params
        # A sole void param (type_id=0, no name) means no params → 'void'
        if len(params) == 1 and params[0].type_id == 0:
            return 'void'
        # Filter out any void (type_id=0) params in a multi-param list
        params = [p for p in params if p.type_id != 0]
        return ', '.join(self._param_str(p, depth) for p in params) or 'void'

    def _member_decl(self, m: BtfMember, indent: str) -> str:
        name = _sanitize(m.name)
        # Unwrap modifiers to find the base type for special cases
        quals, base_tid = self._strip_modifiers(m.type_id)
        base_t = self.b.get_type(base_tid)
        qual_pfx = ' '.join(quals) + ' ' if quals else ''

        # Array (possibly qualified): type name[dims]
        if isinstance(base_t, BtfArray):
            if not name:
                return ''  # nameless array members are not valid C; skip
            inner = self._type_ref(base_t.elem_type_id)
            dims = f'[{base_t.nelems}]' if base_t.nelems else '[0]'
            # Drop qualifiers already present in element type (e.g. const array of const char)
            deduped_quals = [q for q in quals if q not in inner.split()]
            qp = ' '.join(deduped_quals) + ' ' if deduped_quals else ''
            return f'{indent}{qp}{inner} {name}{dims};'

        # Pointer(s)-to-array (possibly qualified): type ([quals] *...name)[dims]
        arr_parts = self._ptr_to_array_parts(m.type_id)
        if arr_parts is not None:
            inner, stars, dims, arr_quals = arr_parts
            aq = ' ' + ' '.join(arr_quals) if arr_quals else ''
            line = f'{inner} ({stars}{aq} {name}){dims};'.replace('  ', ' ')
            return f'{indent}{line}'

        # Function proto or pointer-to-func-proto (possibly qualified):
        # ret (* qual name)(params)
        fp = self._funcptr_parts(m.type_id)
        if fp is not None:
            ret, params, fp_quals = fp
            qual_mid = ' '.join(fp_quals) + ' ' if fp_quals else ''
            line = f'{ret} (*{qual_mid}{name or ""})({params});'
            return f'{indent}{line}'

        # Bitfield
        if m.bitfield_size:
            ref = self._type_ref(m.type_id)
            return f'{indent}{ref} {name} : {m.bitfield_size};'

        # General case
        ref = self._type_ref(m.type_id)
        line = f'{ref} {name};' if name else f'{ref};'
        return f'{indent}{line}'

    # ------------------------------------------------------------------
    # Emit helpers
    # ------------------------------------------------------------------

    def _emit(self, line: str = '') -> None:
        self._out.append(line)

    def _emit_forward(self, kw: str, name: str) -> None:
        key = f'{kw} {name}'
        if key in self._fwd_emitted:
            return
        # Check for cross-tag conflicts (e.g. struct X already defined, don't emit union X)
        for other_kw in ('struct', 'union', 'enum'):
            if other_kw != kw and f'{other_kw} {name}' in self._emitted_names:
                return
        self._fwd_emitted.add(key)
        self._emit(f'{kw} {name};')

    # ------------------------------------------------------------------
    # Ensure a type's forward declaration exists before a struct body
    # that references it by pointer (so we don't need the full def yet).
    # ------------------------------------------------------------------

    def _ensure_forward(self, type_id: int) -> None:
        t = self.b.get_type(type_id)
        if t is None:
            return
        if isinstance(t, (BtfStruct, BtfUnion)) and t.name:
            kw = 'struct' if isinstance(t, BtfStruct) else 'union'
            self._emit_forward(kw, _sanitize(t.name))
        elif isinstance(t, BtfFwd) and t.name:
            self._emit_forward(t.fwd_kind, _sanitize(t.name))

    # ------------------------------------------------------------------
    # Full type definitions
    # ------------------------------------------------------------------

    def _emit_int(self, t: BtfInt) -> None:
        # INT types are built-ins; emit nothing (they appear via typedef)
        pass

    def _emit_float(self, t: BtfFloat) -> None:
        pass

    def _emit_enum(self, t: 'BtfEnum | BtfEnum64', type_id: int) -> None:
        name = self._tag_renames.get(type_id, _sanitize(t.name))
        seen_vals: set[int] = set()
        values = []
        for v in t.values:
            vname = _sanitize(v.name)
            if v.value not in seen_vals and vname not in self._emitted_names:
                seen_vals.add(v.value)
                self._emitted_names.add(vname)
                values.append(v)

        # Use __attribute__((packed)) on enums smaller than default (4 bytes)
        # to match kernel's enum sizing (e.g. -fshort-enums or packed enums)
        enum_packed = ' __attribute__((packed))' if t.size < 4 else ''
        if name:
            self._emit(f'enum{enum_packed} {name} {{')
        else:
            self._emit(f'enum{enum_packed} {{')
        if not values:
            # All values deduped; emit a unique placeholder to avoid empty enum
            self._emit(f'\t__btf_enum_{type_id}_pad__ = 0')
        else:
            for i, v in enumerate(values):
                comma = ',' if i < len(values) - 1 else ''
                vname = _sanitize(v.name)
                val_str = str(v.value)
                if v.value > 0x7FFFFFFF:
                    val_str += 'ULL'
                elif v.value < -0x80000000:
                    val_str += 'LL'
                self._emit(f'\t{vname} = {val_str}{comma}')
        self._emit('};')

    def _unwrap_modifiers(self, tid: int) -> int:
        """Unwrap only modifiers (const/volatile/restrict/type_tag), not typedefs."""
        while True:
            t = self.b.get_type(tid)
            if isinstance(t, BtfModifier):
                tid = t.modified_type_id
            else:
                return tid

    def _unwrap_tid(self, tid: int) -> int:
        """Unwrap modifiers and typedefs to reach the base type_id."""
        while True:
            t = self.b.get_type(tid)
            if isinstance(t, BtfModifier):
                tid = t.modified_type_id
            elif isinstance(t, BtfTypedef):
                tid = t.referred_type_id
            else:
                return tid

    def _ensure_forward_typedef(self, type_id: int) -> None:
        """Emit a forward typedef (struct foo_s; typedef struct foo_s foo_t;) to break cycles."""
        if type_id in self._typedef_output:
            return
        t = self.b.get_type(type_id)
        if not isinstance(t, BtfTypedef):
            return
        name = _sanitize(t.name)
        if not name:
            return
        ref_t = self.b.get_type(t.referred_type_id)
        if isinstance(ref_t, (BtfStruct, BtfUnion)) and ref_t.name:
            kw = 'struct' if isinstance(ref_t, BtfStruct) else 'union'
            sname = _sanitize(ref_t.name)
            self._emit_forward(kw, sname)
            self._typedef_output.add(type_id)
            self._emit(f'typedef {kw} {sname} {name};')

    def _is_anon(self, type_id: int) -> bool:
        """True if type_id (after stripping modifiers only) is an unnamed struct/union."""
        t = self.b.get_type(self._unwrap_modifiers(type_id))
        return isinstance(t, (BtfStruct, BtfUnion)) and not t.name

    def _collect_member_deps(self, members: list[BtfMember]) -> list[int]:
        """Return type_ids that must be fully emitted before this struct body.
        Anonymous structs/unions/enums are excluded — they are inlined instead,
        but their own deps are collected recursively."""
        deps = []
        for m in members:
            self._collect_dep(m.type_id, deps)
        return deps

    def _collect_dep(self, type_id: int, deps: list[int]) -> None:
        tid = self._unwrap_modifiers(type_id)
        t = self.b.get_type(tid)
        if isinstance(t, BtfTypedef):
            deps.append(tid)
        elif isinstance(t, BtfFuncProto):
            # Collect deps for return type and all params
            self._collect_dep(t.return_type_id, deps)
            for p in t.params:
                self._collect_dep(p.type_id, deps)
        elif isinstance(t, BtfPtr):
            inner_tid = self._unwrap_modifiers(t.pointee_type_id)
            inner_t = self.b.get_type(inner_tid)
            if isinstance(inner_t, BtfFuncProto):
                # Function pointer: collect return + param deps
                self._collect_dep(inner_t.return_type_id, deps)
                for p in inner_t.params:
                    self._collect_dep(p.type_id, deps)
            elif not isinstance(inner_t, (BtfStruct, BtfUnion)):
                # Pointer-to-typedef or other named type: need full definition
                self._collect_dep(t.pointee_type_id, deps)
            # Pointer-to-struct/union: only a forward decl is needed, no dep
        elif isinstance(t, (BtfStruct, BtfUnion)):
            if t.name:
                deps.append(tid)
            else:
                # Anonymous: inlined, but recurse to collect its deps
                deps.extend(self._collect_member_deps(t.members))
        elif isinstance(t, (BtfEnum, BtfEnum64)):
            if t.name:
                deps.append(tid)
            # Anonymous enum: inlined, no further deps needed
        elif isinstance(t, BtfArray):
            self._collect_dep(t.elem_type_id, deps)

    def _emit_ptr_forward_decls(self, members: list[BtfMember]) -> None:
        """Emit forward declarations for structs/unions referenced by pointer
        anywhere in the member type tree (including inside funcproto params)."""
        to_visit = [m.type_id for m in members]
        seen: set[int] = set()
        while to_visit:
            type_id = to_visit.pop()
            if type_id in seen or type_id == 0:
                continue
            seen.add(type_id)
            tid = self._unwrap_modifiers(type_id)
            t = self.b.get_type(tid)
            if isinstance(t, BtfPtr):
                # Follow pointer chain to find base type
                cur = t.pointee_type_id
                while True:
                    cur_tid = self._unwrap_modifiers(cur)
                    cur_t = self.b.get_type(cur_tid)
                    if isinstance(cur_t, BtfPtr):
                        cur = cur_t.pointee_type_id
                        continue
                    if isinstance(cur_t, (BtfStruct, BtfUnion)) and cur_t.name:
                        kw = 'struct' if isinstance(cur_t, BtfStruct) else 'union'
                        self._emit_forward(kw, self._tag_renames.get(cur_tid, _sanitize(cur_t.name)))
                    elif isinstance(cur_t, BtfFwd) and cur_t.name:
                        self._emit_forward(cur_t.fwd_kind, _sanitize(cur_t.name))
                    elif isinstance(cur_t, BtfFuncProto):
                        to_visit.append(cur_t.return_type_id)
                        to_visit.extend(p.type_id for p in cur_t.params)
                    break
            elif isinstance(t, BtfFuncProto):
                to_visit.append(t.return_type_id)
                to_visit.extend(p.type_id for p in t.params)
            elif isinstance(t, BtfArray):
                to_visit.append(t.elem_type_id)

    def _emit_funcproto_fwd_decls(self, proto: BtfFuncProto) -> None:
        """Emit forward declarations for structs/unions referenced by pointer
        in a funcproto's params and return type."""
        fake_members = [BtfMember(name='', type_id=proto.return_type_id,
                                  bit_offset=0, bitfield_size=0)]
        fake_members.extend(BtfMember(name='', type_id=p.type_id,
                                      bit_offset=0, bitfield_size=0)
                            for p in proto.params)
        self._emit_ptr_forward_decls(fake_members)

    def _type_size(self, type_id: int) -> int | None:
        """Return the byte size of a BTF type, or None if unknown."""
        if type_id == 0:
            return 0
        t = self.b.get_type(type_id)
        if t is None:
            return None
        if isinstance(t, BtfInt):
            return t.size
        if isinstance(t, BtfFloat):
            return t.size
        if isinstance(t, BtfPtr):
            return 8
        if isinstance(t, BtfArray):
            elem_size = self._type_size(t.elem_type_id)
            return elem_size * t.nelems if elem_size is not None else None
        if isinstance(t, (BtfStruct, BtfUnion)):
            # If this type_id was renamed (duplicate with different size),
            # use the renamed key; otherwise check the original name.
            if t.name:
                kw = 'struct' if isinstance(t, BtfStruct) else 'union'
                renamed = self._tag_renames.get(type_id)
                key = f'{kw} {renamed}' if renamed else f'{kw} {_sanitize(t.name)}'
                if key in self._emitted_sizes:
                    return self._emitted_sizes[key]
            return t.size
        if isinstance(t, (BtfEnum, BtfEnum64)):
            return t.size
        if isinstance(t, BtfTypedef):
            return self._type_size(t.referred_type_id)
        if isinstance(t, BtfModifier):
            return self._type_size(t.modified_type_id)
        return None

    def _offset_comment(self, m: BtfMember) -> str:
        """Return a comment string annotating the member's offset."""
        byte_off = m.bit_offset // 8
        bit_rem = m.bit_offset % 8
        if m.bitfield_size or bit_rem:
            return f' /* 0x{byte_off:x}:{bit_rem} */'
        return f' /* 0x{byte_off:x} */'

    def _emit_padding(self, indent: str, gap: int) -> None:
        """Emit explicit padding bytes."""
        self._emit(f'{indent}char __pad{self._pad_idx}[{gap}];')
        self._pad_idx += 1

    def _bitfield_group_size(self, group: list[BtfMember],
                             next_byte: int) -> int:
        """Compute byte size for a bitfield group.

        Uses the storage unit implied by each bitfield's declared type,
        but caps at next_byte (next non-bitfield member offset or struct size)
        to handle packed kernel structs where storage units are truncated.
        """
        group_start_byte = group[0].bit_offset // 8
        # Compute the max storage end from the declared types
        max_type_end = 0
        for bf in group:
            ts = self._type_size(bf.type_id) or 1
            storage_bits = ts * 8
            unit_start = (bf.bit_offset // storage_bits) * ts
            max_type_end = max(max_type_end, unit_start + ts)
        # Cap at available space (handles packed kernel structs)
        group_end = min(max_type_end, next_byte)
        # But ensure we cover all the bits used
        bits_end = group[-1].bit_offset + group[-1].bitfield_size
        min_end = (bits_end + 7) // 8
        group_end = max(group_end, min_end)
        return group_end - group_start_byte

    def _emit_bitfield_group(self, group: list[BtfMember],
                             group_size: int, indent: str) -> None:
        """Emit a bitfield group as an opaque integer field."""
        start_byte = group[0].bit_offset // 8
        # Build comment listing the bitfields
        parts = []
        for bf in group:
            name = _sanitize(bf.name)
            rel_bit = bf.bit_offset - start_byte * 8
            parts.append(f'{name}:{rel_bit}:{bf.bitfield_size}')
        comment = f' /* 0x{start_byte:x} - {", ".join(parts)} */'
        # Choose type
        type_map = {1: 'unsigned char', 2: 'unsigned short',
                    4: 'unsigned int', 8: 'unsigned long long'}
        type_str = type_map.get(group_size)
        idx = self._pad_idx
        self._pad_idx += 1
        if type_str:
            self._emit(f'{indent}{type_str} __bitfields{idx};{comment}')
        else:
            self._emit(f'{indent}char __bitfields{idx}[{group_size}];{comment}')

    def _emit_struct_body(self, t: 'BtfStruct | BtfUnion', indent: str) -> None:
        """Emit members of a struct/union at the given indent level,
        inserting explicit padding to match kernel layout."""
        is_union = isinstance(t, BtfUnion)
        cur_byte = 0
        members = t.members
        i = 0

        while i < len(members):
            m = members[i]

            # Handle bitfield groups (consecutive bitfield members) for structs
            if m.bitfield_size and not is_union:
                group_start = i
                while i < len(members) and members[i].bitfield_size:
                    i += 1
                group = members[group_start:i]
                group_start_byte = group[0].bit_offset // 8

                # Determine end boundary
                if i < len(members):
                    next_byte = members[i].bit_offset // 8
                else:
                    next_byte = t.size

                group_size = self._bitfield_group_size(group, next_byte)

                # Padding before the group
                if group_start_byte > cur_byte:
                    self._emit_padding(indent, group_start_byte - cur_byte)
                cur_byte = group_start_byte + group_size

                self._emit_bitfield_group(group, group_size, indent)
                continue

            # For unions, emit bitfields as regular members (all at offset 0)
            member_byte = m.bit_offset // 8

            # Insert padding before this member if there's a gap
            if not is_union and member_byte > cur_byte:
                self._emit_padding(indent, member_byte - cur_byte)
                cur_byte = member_byte

            base_tid = self._unwrap_modifiers(m.type_id)
            base_t = self.b.get_type(base_tid)
            mname = _sanitize(m.name)
            comment = self._offset_comment(m)

            if isinstance(base_t, (BtfStruct, BtfUnion)) and not base_t.name:
                kw = 'struct' if isinstance(base_t, BtfStruct) else 'union'
                self._emit(f'{indent}{kw} {{')
                self._emit_struct_body(base_t, indent + '\t')
                self._emit(f'{indent}}}{" " + mname if mname else ""};{comment}')
            elif isinstance(base_t, BtfArray):
                # Check if element type is anonymous struct/union
                _, elem_tid = self._strip_modifiers(base_t.elem_type_id)
                elem_t = self.b.get_type(elem_tid)
                if isinstance(elem_t, (BtfStruct, BtfUnion)) and not elem_t.name:
                    kw = 'struct' if isinstance(elem_t, BtfStruct) else 'union'
                    dims = f'[{base_t.nelems}]' if base_t.nelems else '[0]'
                    self._emit(f'{indent}{kw} {{')
                    self._emit_struct_body(elem_t, indent + '\t')
                    self._emit(f'{indent}}}{" " + mname + dims if mname else dims};{comment}')
                else:
                    line = self._member_decl(m, indent)
                    if line:
                        self._emit(f'{line}{comment}')
            elif isinstance(base_t, (BtfEnum, BtfEnum64)) and not base_t.name:
                # Inline anonymous enum
                self._emit(f'{indent}enum {{')
                for vi, v in enumerate(base_t.values):
                    comma = ',' if vi < len(base_t.values) - 1 else ''
                    self._emit(f'{indent}\t{_sanitize(v.name)} = {v.value}{comma}')
                self._emit(f'{indent}}}{" " + mname if mname else ""};{comment}')
            else:
                self._emit(f'{self._member_decl(m, indent)}{comment}')

            # Advance cur_byte past this member
            if not is_union:
                msize = self._type_size(m.type_id)
                if msize is not None:
                    cur_byte = member_byte + msize

            i += 1

        # Trailing padding to match the type's declared size
        if not is_union and cur_byte < t.size:
            self._emit_padding(indent, t.size - cur_byte)
        elif is_union and t.size:
            # Ensure union has correct size (alignment padding in kernel)
            self._emit(f'{indent}char __pad_size{self._pad_idx}[{t.size}];')
            self._pad_idx += 1

    def _emit_struct(self, t: 'BtfStruct | BtfUnion', type_id: int) -> None:
        kw = 'struct' if isinstance(t, BtfStruct) else 'union'
        name = self._tag_renames.get(type_id, _sanitize(t.name))

        # Ensure named deps are emitted first
        for dep_id in self._collect_member_deps(t.members):
            self._emit_type(dep_id)

        # Emit forward declarations for structs/unions referenced by pointer
        # inside function pointer parameters (they don't need full definitions,
        # but do need to be visible to avoid "declared inside parameter list")
        self._emit_ptr_forward_decls(t.members)

        header = f'{kw} {name}' if name else kw
        if name:
            self._emitted_sizes[f'{kw} {name}'] = t.size
        if not t.members:
            self._emit(f'{header} {{}};')
            return

        self._emit('#pragma pack(push, 1)')
        self._emit(f'{header} {{')
        self._emit_struct_body(t, '\t')
        self._emit('};')
        self._emit('#pragma pack(pop)')
        if name and t.size:
            self._emit(f'_Static_assert(sizeof({kw} {name}) == {t.size}, "unexpected size for {kw} {name}");')

    def _emit_typedef(self, t: BtfTypedef, type_id: int) -> None:
        name = _sanitize(t.name)
        if not name:
            return
        if name in self._typedef_names:
            return
        self._typedef_names.add(name)

        # Ensure the referred type is defined
        self._emit_type(t.referred_type_id)

        ref_t = self.b.get_type(t.referred_type_id)

        # typedef to func proto / pointer-to-func-proto: special syntax
        proto = None
        if isinstance(ref_t, BtfFuncProto):
            proto = ref_t
        elif isinstance(ref_t, BtfPtr):
            pt = self.b.get_type(ref_t.pointee_type_id)
            if isinstance(pt, BtfFuncProto):
                proto = pt
        if proto is not None:
            self._emit_funcproto_fwd_decls(proto)
            ret = self._type_ref(proto.return_type_id)
            params = self._proto_params_str(proto)
            if type_id not in self._typedef_output:
                self._typedef_output.add(type_id)
                if isinstance(ref_t, BtfPtr):
                    self._emit(f'typedef {ret} (*{name})({params});')
                else:
                    self._emit(f'typedef {ret} ({name})({params});')
            return

        # typedef to pointer-to-array (possibly through modifiers):
        # typedef type (* [quals] name)[dims]
        ref_quals, ref_base_tid = self._strip_modifiers(t.referred_type_id)
        ref_base_t = self.b.get_type(ref_base_tid)
        if isinstance(ref_base_t, BtfPtr):
            _, arr_tid = self._strip_modifiers(ref_base_t.pointee_type_id)
            arr_t = self.b.get_type(arr_tid)
            if isinstance(arr_t, BtfArray):
                inner = self._type_ref(arr_t.elem_type_id)
                dims = f'[{arr_t.nelems}]' if arr_t.nelems else '[0]'
                qual_sfx = ' ' + ' '.join(ref_quals) if ref_quals else ''
                if type_id not in self._typedef_output:
                    self._typedef_output.add(type_id)
                    self._emit(f'typedef {inner} (*{qual_sfx} {name}){dims};')
                return

        # typedef to anonymous struct/union: emit inline body
        if isinstance(ref_t, (BtfStruct, BtfUnion)) and not ref_t.name:
            kw = 'struct' if isinstance(ref_t, BtfStruct) else 'union'
            # Ensure deps of the anonymous type are emitted first
            for dep_id in self._collect_member_deps(ref_t.members):
                self._emit_type(dep_id)
            if type_id not in self._typedef_output:
                self._typedef_output.add(type_id)
                self._emit('#pragma pack(push, 1)')
                self._emit(f'typedef {kw} {{')
                self._emit_struct_body(ref_t, '\t')
                self._emit(f'}} {name};')
                self._emit('#pragma pack(pop)')
            return

        # typedef to anonymous enum: emit inline body
        if isinstance(ref_t, (BtfEnum, BtfEnum64)) and not ref_t.name:
            if type_id not in self._typedef_output:
                self._typedef_output.add(type_id)
                self._emit(f'typedef enum {{')
                for i, v in enumerate(ref_t.values):
                    comma = ',' if i < len(ref_t.values) - 1 else ''
                    self._emit(f'\t{_sanitize(v.name)} = {v.value}{comma}')
                self._emit(f'}} {name};')
            return

        # typedef to array: special syntax
        if isinstance(ref_t, BtfArray):
            inner = self._type_ref(ref_t.elem_type_id)
            dims = f'[{ref_t.nelems}]' if ref_t.nelems else '[]'
            if type_id not in self._typedef_output:
                self._typedef_output.add(type_id)
                self._emit(f'typedef {inner} {name}{dims};')
            return

        if type_id not in self._typedef_output:
            self._typedef_output.add(type_id)
            ref_str = self._type_ref(t.referred_type_id)
            self._emit(f'typedef {ref_str} {name};')

    def _emit_fwd(self, t: BtfFwd) -> None:
        name = _sanitize(t.name)
        if name:
            self._emit_forward(t.fwd_kind, name)

    # ------------------------------------------------------------------
    # Main emit dispatcher — idempotent
    # ------------------------------------------------------------------

    def _emit_type(self, type_id: int) -> None:
        if type_id == 0:
            return
        if type_id in self._emitted:
            # Cycle detected — if this is a typedef not yet output, forward-declare it
            t = self.b.get_type(type_id)
            if isinstance(t, BtfTypedef):
                self._ensure_forward_typedef(type_id)
            return
        t = self.b.get_type(type_id)
        if t is None:
            return

        # Mark first to break cycles
        self._emitted.add(type_id)

        if isinstance(t, (BtfInt, BtfFloat)):
            return  # built-ins, no emission needed

        if isinstance(t, BtfPtr):
            pt = self.b.get_type(t.pointee_type_id)
            if isinstance(pt, (BtfStruct, BtfUnion)) and pt.name:
                # Struct/union pointer: only a forward decl is needed
                kw = 'struct' if isinstance(pt, BtfStruct) else 'union'
                self._emit_forward(kw, _sanitize(pt.name))
            elif isinstance(pt, BtfTypedef):
                # Typedef pointer: ensure the typedef is emitted (handles cycles)
                self._emit_type(t.pointee_type_id)
            elif isinstance(pt, BtfFuncProto):
                # Pointer-to-funcproto: emit return + param deps
                self._emit_type(pt.return_type_id)
                for p in pt.params:
                    self._emit_type(p.type_id)
            return

        if isinstance(t, BtfModifier):
            self._emit_type(t.modified_type_id)
            return

        if isinstance(t, BtfArray):
            self._emit_type(t.elem_type_id)
            return

        if isinstance(t, BtfFwd):
            self._emit_fwd(t)
            return

        if isinstance(t, (BtfEnum, BtfEnum64)):
            if not t.name:
                return  # anonymous — inlined at point of use
            sname = _sanitize(t.name)
            key = f'enum {sname}'
            if key in self._emitted_names:
                # Same-tag duplicate with different size → rename
                emitted_size = self._emitted_sizes.get(key)
                if emitted_size is not None and emitted_size != t.size:
                    sname = f'{sname}____{type_id}'
                    key = f'enum {sname}'
                    self._tag_renames[type_id] = sname
                else:
                    return
            # Cross-tag conflict: rename
            if f'struct {sname}' in self._emitted_names or f'union {sname}' in self._emitted_names:
                sname = f'{sname}____{type_id}'
                key = f'enum {sname}'
                self._tag_renames[type_id] = sname
            self._emitted_names.add(key)
            self._emitted_sizes[key] = t.size
            self._emit('')
            self._emit_enum(t, type_id)
            return

        if isinstance(t, (BtfStruct, BtfUnion)):
            if not t.name:
                return  # anonymous — inlined at point of use
            kw = 'struct' if isinstance(t, BtfStruct) else 'union'
            sname = _sanitize(t.name)
            key = f'{kw} {sname}'
            alt_kw = 'union' if kw == 'struct' else 'struct'
            if key in self._emitted_names:
                # Same-tag duplicate with different size → rename
                emitted_size = self._emitted_sizes.get(key)
                if emitted_size is not None and emitted_size != t.size:
                    sname = f'{sname}____{type_id}'
                    key = f'{kw} {sname}'
                    self._tag_renames[type_id] = sname
                else:
                    return
            # Cross-tag conflict: rename
            if f'{alt_kw} {sname}' in self._emitted_names or f'enum {sname}' in self._emitted_names:
                sname = f'{sname}____{type_id}'
                key = f'{kw} {sname}'
                self._tag_renames[type_id] = sname
            self._emitted_names.add(key)
            self._emit('')
            self._emit_struct(t, type_id)
            return

        if isinstance(t, BtfTypedef):
            self._emit('')
            self._emit_typedef(t, type_id)
            return

        if isinstance(t, BtfFuncProto):
            # Emit return and param types
            self._emit_type(t.return_type_id)
            for p in t.params:
                self._emit_type(p.type_id)
            return

        if isinstance(t, BtfFunc):
            # Emitted separately after type definitions
            return

        if isinstance(t, (BtfVar, BtfDatasec, BtfDeclTag)):
            return

    # ------------------------------------------------------------------
    # Function pointer emission
    # ------------------------------------------------------------------

    def _func_proto_c(self, name: str, proto: BtfFuncProto) -> str:
        """Return 'ret (*name)(params)' string."""
        ret = self._type_ref(proto.return_type_id)
        params = self._proto_params_str(proto)
        return f'{ret} (*{name})({params})'

    def _emit_funcs(self) -> None:
        """Emit all FUNC types as typed function pointers using kallsyms addresses."""
        for type_id in sorted(self.b.types.keys()):
            t = self.b.get_type(type_id)
            if not isinstance(t, BtfFunc):
                continue
            name = t.name
            if not name or not _is_valid_c_ident(name):
                continue
            # Skip if name conflicts with an emitted enum value or type name
            if name in self._emitted_names:
                continue
            addr = self.kallsyms.get(name)
            if addr is None:
                continue
            proto = self.b.get_type(t.proto_type_id)
            if not isinstance(proto, BtfFuncProto):
                continue
            decl = self._func_proto_c(name, proto)
            cast = self._func_proto_c('', proto)
            self._emit(f'static {decl} = ({cast})0x{addr:016x}UL;')

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate(self) -> str:
        self._out = []
        self._emitted = set()
        self._typedef_output = set()
        self._emitted_names = set()
        self._typedef_names = set()
        self._fwd_emitted = set()
        self._tag_renames = {}
        self._emitted_sizes = {}
        self._pad_idx = 0

        self._emit('/* THIS FILE IS AUTOGENERATED BY gen_vmlinux_h.py */')
        self._emit('#ifndef __VMLINUX_H__')
        self._emit('#define __VMLINUX_H__')
        self._emit('')
        if self.vermagic:
            self._emit(f'#define VERMAGIC "{self.vermagic}"')
            self._emit('')

        # Emit all types in order
        for type_id in sorted(self.b.types.keys()):
            self._emit_type(type_id)

        if self.kallsyms:
            self._emit('')
            self._emit_funcs()

        self._emit('')
        self._emit('#endif /* __VMLINUX_H__ */')

        return '\n'.join(self._out) + '\n'


# ---------------------------------------------------------------------------
# kallsyms
# ---------------------------------------------------------------------------

def load_kallsyms(path: str) -> dict[str, int]:
    """Parse a kallsyms file, returning name -> address for text symbols."""
    syms: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr_s, type_s, name = parts[0], parts[1], parts[2]
            if type_s not in ('T', 't'):
                continue
            try:
                syms[name] = int(addr_s, 16)
            except ValueError:
                continue
    return syms


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <manifest.json> [output]', file=sys.stderr)
        sys.exit(1)
    manifest_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'vmlinux.h'

    with open(manifest_path) as f:
        manifest = json.load(f)

    btf_path = manifest['btf']
    kallsyms_path = manifest.get('kallsyms')
    vermagic = manifest.get('vermagic')

    print(f'Parsing {btf_path}...', file=sys.stderr)
    b = btf.parse_file(btf_path)
    print(f'  {len(b.types)} types loaded', file=sys.stderr)

    kallsyms: dict[str, int] = {}
    if kallsyms_path:
        print(f'Loading {kallsyms_path}...', file=sys.stderr)
        kallsyms = load_kallsyms(kallsyms_path)
        print(f'  {len(kallsyms)} text symbols loaded', file=sys.stderr)

    gen = Generator(b, kallsyms, vermagic)
    print('Generating...', file=sys.stderr)
    output = gen.generate()

    if out_path == '-':
        sys.stdout.write(output)
    else:
        with open(out_path, 'w') as f:
            f.write(output)
        lines = output.count('\n')
        print(f'Written {lines} lines to {out_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
