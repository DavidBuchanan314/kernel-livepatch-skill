"""
BTF (BPF Type Format) parser.

Parses the binary BTF format as specified at:
https://docs.kernel.org/bpf/btf.html
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BTF_MAGIC = 0xEB9F
BTF_VERSION = 1

# info field layout
_INFO_VLEN_MASK = 0xFFFF
_INFO_KIND_SHIFT = 24
_INFO_KIND_MASK = 0x1F
_INFO_KIND_FLAG = 1 << 31

# BTF_KIND_INT extra encoding
_INT_ENCODING_SHIFT = 24
_INT_ENCODING_MASK = 0x0F
_INT_OFFSET_SHIFT = 16
_INT_OFFSET_MASK = 0xFF
_INT_BITS_MASK = 0xFF

# BTF_KIND_STRUCT/UNION member bitfield (kind_flag=1)
_MEMBER_BITFIELD_SIZE_SHIFT = 24
_MEMBER_BIT_OFFSET_MASK = 0xFFFFFF


class BtfKind(IntEnum):
    UNKNOWN = 0
    INT = 1
    PTR = 2
    ARRAY = 3
    STRUCT = 4
    UNION = 5
    ENUM = 6
    FWD = 7
    TYPEDEF = 8
    VOLATILE = 9
    CONST = 10
    RESTRICT = 11
    FUNC = 12
    FUNC_PROTO = 13
    VAR = 14
    DATASEC = 15
    FLOAT = 16
    DECL_TAG = 17
    TYPE_TAG = 18
    ENUM64 = 19


class IntEncoding(IntEnum):
    NONE = 0
    SIGNED = 1 << 0
    CHAR = 1 << 1
    BOOL = 1 << 2


class FuncLinkage(IntEnum):
    STATIC = 0
    GLOBAL = 1
    EXTERN = 2


class VarLinkage(IntEnum):
    STATIC = 0
    GLOBAL_ALLOCATED = 1
    GLOBAL_EXTERN = 2


# ---------------------------------------------------------------------------
# Type dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BtfType:
    """Base for all BTF types."""
    type_id: int
    name: str  # resolved from string table
    kind: BtfKind
    kind_flag: bool


@dataclass
class BtfInt(BtfType):
    size: int            # bytes
    encoding: IntEncoding
    bit_offset: int      # usually 0
    bits: int            # bit width


@dataclass
class BtfPtr(BtfType):
    pointee_type_id: int


@dataclass
class BtfArray(BtfType):
    elem_type_id: int
    index_type_id: int
    nelems: int


@dataclass
class BtfMember:
    name: str
    type_id: int
    bit_offset: int      # always the bit offset
    bitfield_size: int   # 0 means not a bitfield


@dataclass
class BtfStruct(BtfType):
    size: int
    members: list[BtfMember] = field(default_factory=list)


@dataclass
class BtfUnion(BtfType):
    size: int
    members: list[BtfMember] = field(default_factory=list)


@dataclass
class BtfEnumValue:
    name: str
    value: int  # signed for ENUM, may be negative


@dataclass
class BtfEnum(BtfType):
    size: int
    signed: bool
    values: list[BtfEnumValue] = field(default_factory=list)


@dataclass
class BtfEnum64(BtfType):
    size: int
    signed: bool
    values: list[BtfEnumValue] = field(default_factory=list)


@dataclass
class BtfFwd(BtfType):
    fwd_kind: str   # 'struct' or 'union'


@dataclass
class BtfTypedef(BtfType):
    referred_type_id: int


@dataclass
class BtfModifier(BtfType):
    """Covers VOLATILE, CONST, RESTRICT, TYPE_TAG."""
    modified_type_id: int


@dataclass
class BtfParam:
    name: str
    type_id: int


@dataclass
class BtfFunc(BtfType):
    proto_type_id: int
    linkage: FuncLinkage


@dataclass
class BtfFuncProto(BtfType):
    return_type_id: int
    params: list[BtfParam] = field(default_factory=list)


@dataclass
class BtfVar(BtfType):
    var_type_id: int
    linkage: VarLinkage


@dataclass
class BtfVarSecInfo:
    type_id: int
    offset: int
    size: int


@dataclass
class BtfDatasec(BtfType):
    sec_size: int
    vars: list[BtfVarSecInfo] = field(default_factory=list)


@dataclass
class BtfFloat(BtfType):
    size: int


@dataclass
class BtfDeclTag(BtfType):
    referred_type_id: int
    component_idx: int   # -1 means the type itself


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

_HEADER_FMT = "<HBBIIiIi"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 24 bytes

@dataclass
class BtfHeader:
    magic: int
    version: int
    flags: int
    hdr_len: int
    type_off: int
    type_len: int
    str_off: int
    str_len: int


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class BtfParseError(Exception):
    pass


class Btf:
    """Parsed representation of a BTF blob."""

    def __init__(self, data: bytes):
        self._data = data
        self.header: BtfHeader = self._parse_header()
        self._str_section: bytes = self._slice_str_section()
        self.types: dict[int, BtfType] = {}
        self._parse_types()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_type(self, type_id: int) -> Optional[BtfType]:
        """Return the BtfType for *type_id*, or None for void (0)."""
        if type_id == 0:
            return None
        return self.types.get(type_id)

    def resolve_name(self, type_id: int) -> str:
        """Walk typedefs/modifiers to find the first named type."""
        seen: set[int] = set()
        while type_id and type_id not in seen:
            seen.add(type_id)
            t = self.types.get(type_id)
            if t is None:
                break
            if t.name:
                return t.name
            if isinstance(t, (BtfTypedef, BtfModifier, BtfPtr)):
                type_id = (
                    t.referred_type_id
                    if isinstance(t, BtfTypedef)
                    else t.modified_type_id
                    if isinstance(t, BtfModifier)
                    else t.pointee_type_id
                )
            else:
                break
        return ""

    def types_by_kind(self, kind: BtfKind) -> list[BtfType]:
        return [t for t in self.types.values() if t.kind == kind]

    def find_func(self, name: str) -> Optional["BtfFunc"]:
        """Find a FUNC type by name."""
        for t in self.types.values():
            if t.kind == BtfKind.FUNC and t.name == name:
                return t  # type: ignore[return-value]
        return None

    # ------------------------------------------------------------------
    # Internal parsing
    # ------------------------------------------------------------------

    def _parse_header(self) -> BtfHeader:
        if len(self._data) < _HEADER_SIZE:
            raise BtfParseError("Data too short for BTF header")
        fields = struct.unpack_from(_HEADER_FMT, self._data, 0)
        hdr = BtfHeader(*fields)
        if hdr.magic != BTF_MAGIC:
            raise BtfParseError(f"Bad BTF magic: 0x{hdr.magic:04x}")
        if hdr.version != BTF_VERSION:
            raise BtfParseError(f"Unsupported BTF version: {hdr.version}")
        return hdr

    def _slice_str_section(self) -> bytes:
        base = self.header.hdr_len
        off = base + self.header.str_off
        end = off + self.header.str_len
        if end > len(self._data):
            raise BtfParseError("String section out of bounds")
        section = self._data[off:end]
        if not section or section[0] != 0:
            raise BtfParseError("String section must start with null byte")
        return section

    def _get_str(self, offset: int) -> str:
        if offset >= len(self._str_section):
            raise BtfParseError(f"String offset {offset} out of bounds")
        end = self._str_section.index(b'\x00', offset)
        return self._str_section[offset:end].decode('utf-8', errors='replace')

    def _parse_types(self) -> None:
        base = self.header.hdr_len + self.header.type_off
        end = base + self.header.type_len
        pos = base
        type_id = 1

        while pos < end:
            if pos + 12 > end:
                raise BtfParseError(f"Truncated btf_type at offset {pos}")

            name_off, info, size_or_type = struct.unpack_from("<III", self._data, pos)
            pos += 12

            vlen = info & _INFO_VLEN_MASK
            kind_val = (info >> _INFO_KIND_SHIFT) & _INFO_KIND_MASK
            kflag = bool(info & _INFO_KIND_FLAG)
            name = self._get_str(name_off)

            try:
                kind = BtfKind(kind_val)
            except ValueError:
                raise BtfParseError(f"Unknown BTF kind {kind_val} at type_id {type_id}")

            t, pos = self._parse_type_body(
                type_id, name, kind, kflag, vlen, size_or_type, pos
            )
            self.types[type_id] = t
            type_id += 1

    def _parse_type_body(
        self,
        type_id: int,
        name: str,
        kind: BtfKind,
        kflag: bool,
        vlen: int,
        size_or_type: int,
        pos: int,
    ) -> tuple["BtfType", int]:

        if kind == BtfKind.INT:
            extra, = struct.unpack_from("<I", self._data, pos)
            pos += 4
            encoding = IntEncoding((extra >> _INT_ENCODING_SHIFT) & _INT_ENCODING_MASK)
            bit_offset = (extra >> _INT_OFFSET_SHIFT) & _INT_OFFSET_MASK
            bits = extra & _INT_BITS_MASK
            return BtfInt(type_id, name, kind, kflag, size_or_type, encoding,
                          bit_offset, bits), pos

        elif kind == BtfKind.PTR:
            return BtfPtr(type_id, name, kind, kflag, size_or_type), pos

        elif kind == BtfKind.ARRAY:
            elem_type, index_type, nelems = struct.unpack_from("<III", self._data, pos)
            pos += 12
            return BtfArray(type_id, name, kind, kflag, elem_type, index_type, nelems), pos

        elif kind in (BtfKind.STRUCT, BtfKind.UNION):
            members = []
            for _ in range(vlen):
                m_name_off, m_type, m_offset = struct.unpack_from("<III", self._data, pos)
                pos += 12
                m_name = self._get_str(m_name_off)
                if kflag:
                    bitfield_size = m_offset >> _MEMBER_BITFIELD_SIZE_SHIFT
                    bit_offset = m_offset & _MEMBER_BIT_OFFSET_MASK
                else:
                    bitfield_size = 0
                    bit_offset = m_offset
                members.append(BtfMember(name=m_name, type_id=m_type,
                                         bit_offset=bit_offset,
                                         bitfield_size=bitfield_size))
            if kind == BtfKind.STRUCT:
                return BtfStruct(type_id, name, kind, kflag, size_or_type, members), pos
            else:
                return BtfUnion(type_id, name, kind, kflag, size_or_type, members), pos

        elif kind == BtfKind.ENUM:
            values = []
            for _ in range(vlen):
                e_name_off, e_val = struct.unpack_from("<Ii", self._data, pos)
                pos += 8
                values.append(BtfEnumValue(name=self._get_str(e_name_off), value=e_val))
            return BtfEnum(type_id, name, kind, kflag, size_or_type, kflag, values), pos

        elif kind == BtfKind.ENUM64:
            values = []
            for _ in range(vlen):
                e_name_off, val_lo, val_hi = struct.unpack_from("<III", self._data, pos)
                pos += 12
                val = (val_hi << 32) | val_lo
                if kflag and (val >> 63):
                    val -= (1 << 64)
                values.append(BtfEnumValue(name=self._get_str(e_name_off), value=val))
            return BtfEnum64(type_id, name, kind, kflag, size_or_type, kflag, values), pos

        elif kind == BtfKind.FWD:
            return BtfFwd(type_id, name, kind, kflag, 'union' if kflag else 'struct'), pos

        elif kind == BtfKind.TYPEDEF:
            return BtfTypedef(type_id, name, kind, kflag, size_or_type), pos

        elif kind in (BtfKind.VOLATILE, BtfKind.CONST, BtfKind.RESTRICT,
                      BtfKind.TYPE_TAG):
            return BtfModifier(type_id, name, kind, kflag, size_or_type), pos

        elif kind == BtfKind.FUNC:
            try:
                linkage = FuncLinkage(vlen)
            except ValueError:
                linkage = FuncLinkage.STATIC
            return BtfFunc(type_id, name, kind, kflag, size_or_type, linkage), pos

        elif kind == BtfKind.FUNC_PROTO:
            params = []
            for _ in range(vlen):
                p_name_off, p_type = struct.unpack_from("<II", self._data, pos)
                pos += 8
                params.append(BtfParam(name=self._get_str(p_name_off), type_id=p_type))
            return BtfFuncProto(type_id, name, kind, kflag, size_or_type, params), pos

        elif kind == BtfKind.VAR:
            linkage_val, = struct.unpack_from("<I", self._data, pos)
            pos += 4
            try:
                linkage = VarLinkage(linkage_val)
            except ValueError:
                linkage = VarLinkage.STATIC
            return BtfVar(type_id, name, kind, kflag, size_or_type, linkage), pos

        elif kind == BtfKind.DATASEC:
            vars_ = []
            for _ in range(vlen):
                v_type, v_off, v_size = struct.unpack_from("<III", self._data, pos)
                pos += 12
                vars_.append(BtfVarSecInfo(type_id=v_type, offset=v_off, size=v_size))
            return BtfDatasec(type_id, name, kind, kflag, size_or_type, vars_), pos

        elif kind == BtfKind.FLOAT:
            return BtfFloat(type_id, name, kind, kflag, size_or_type), pos

        elif kind == BtfKind.DECL_TAG:
            component_idx, = struct.unpack_from("<i", self._data, pos)
            pos += 4
            return BtfDeclTag(type_id, name, kind, kflag, size_or_type, component_idx), pos

        else:
            # UNKNOWN or unrecognised — skip (no extra data defined)
            return BtfType(type_id, name, kind, kflag), pos


# ---------------------------------------------------------------------------
# Convenience loader
# ---------------------------------------------------------------------------

def parse_file(path: str) -> Btf:
    """Load and parse a BTF file (e.g. /sys/kernel/btf/vmlinux)."""
    with open(path, "rb") as f:
        data = f.read()
    return Btf(data)
