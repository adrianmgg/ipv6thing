__all__ = ['Address', 'Network']

from enum import Enum, unique as enum_unique, auto as enum_auto
import re
import typing
from typing import Iterator, Literal, assert_never, overload, Union
from collections.abc import Iterable, Iterator

class _DEFAULT_T:
    """class for 'default argument' sentinel"""
_DEFAULT = _DEFAULT_T()
"""sentinel used for default argument value"""

_ADDR_TOKEN_PATTERN = re.compile(r"""
(?P<num>[0-9a-zA-Z]+)         # one hextet in the address. the token will match 5+ characters too, max length is checked during parsing
|(?P<skip>::)                 # '::' skip consecutive blocks of zeros
|(?P<sep>:)                   # ':' separator between hextets. needs to be after the `skip` group to parse properly
|(?:/(?P<prefixlen>[0-9]+))   # a '/123' prefix length
|(?P<unknown>.{1,})           # catch anything that didn't match the others so we put it in our error message
""", re.VERBOSE)

@enum_unique
class _AddrToken(Enum):
    NUM = 'num'
    SKIP = 'skip'
    SEP = 'sep'
    PREFIX_LEN = 'prefixlen'
    UNKNOWN = 'unknown'
assert set(a.value for a in _AddrToken) == set(_ADDR_TOKEN_PATTERN.groupindex.keys())

@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[True], require_prefix: Literal[True]) -> tuple[int, int]: ...
@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[True], require_prefix: bool = False) -> tuple[int, int | None]: ...
@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[False] = False) -> int: ...
@overload
def _parse_address(addr: str, /, *, allow_prefix: bool = False, require_prefix: bool = False) -> int | tuple[int, int | None]: ...
def _parse_address(addr: str, /, *, allow_prefix: bool = False, require_prefix: bool = False) -> int | tuple[int, int | None]:
    str_pos = 0
    cur_part = 0
    did_skip: bool = False
    lo: int = 0
    hi: int = 0
    prefix_len: int | None = None
    while (match := _ADDR_TOKEN_PATTERN.match(addr, str_pos)) is not None:
        token = _AddrToken(match.lastgroup)
        lexeme_text: str = match.group(token.value)  # TODO give this var a better name
        if prefix_len is not None:
            raise ValueError('nothing is allowed after the prefix length of the address')
        match token:
            case _AddrToken.NUM:
                # (since the num group can be any length, we don't need to worry about checking for two nums in a row with no separator)
                if len(lexeme_text) > 4:
                    raise ValueError('hextet must be 4 digits or less')
                val = int(lexeme_text, base=16)
                if did_skip:
                    lo <<= 16
                    lo |= val
                else:
                    hi |= val << ((7 - cur_part) * 16)
                cur_part += 1
            case _AddrToken.SKIP:
                if did_skip:
                    raise ValueError("address can only have one '::'")  # TODO show offending token in context
                did_skip = True
            case _AddrToken.SEP:
                pass
            case _AddrToken.PREFIX_LEN:
                prefix_len = int(lexeme_text, base=10)
            case _AddrToken.UNKNOWN:
                raise ValueError(f'address parser unable to parse {lexeme_text!r}')  # TODO give this a better message
            case _ as unreachable:
                assert_never(unreachable)
        str_pos = match.end()
    if require_prefix and prefix_len is None:
        raise ValueError('no prefix length specified')
    if allow_prefix:
        return (lo | hi), prefix_len
    else:
        return lo | hi

_MIN_IPV6_ADDR_VAL = 0x0000_0000_0000_0000_0000_0000_0000_0000
_MAX_IPV6_ADDR_VAL = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF

class _CompressMode(Enum):
    COMPRESS = enum_auto()
    EXPAND   = enum_auto()

class _PadMode(Enum):
    PAD      = enum_auto()
    TRIM     = enum_auto()

class _AddressFormatSpecOption(Enum):
    compress: _CompressMode | None
    pad: _PadMode | None

    def __new__(cls, char: str, compress_mode: _CompressMode | None, pad_mode: _PadMode | None) -> '_AddressFormatSpecOption':
        obj = object.__new__(cls)
        obj._value_ = char
        obj.compress = compress_mode
        obj.pad = pad_mode
        return obj

    SHORT_ADDRESS     = 's', _CompressMode.COMPRESS, _PadMode.TRIM
    """shorthand for COMPRESS_ZEROS and TRIM_HEXTETS"""
    LONG_ADDRESS      = 'l', _CompressMode.EXPAND, _PadMode.PAD
    """shorthand for NO_COMPRESS_ZEROS and PAD_HEXTETS"""
    COMPRESS_ZEROS    = 'c', _CompressMode.COMPRESS, None
    """compress zeros with '::' """
    EXPAND_ZEROS      = 'e', _CompressMode.EXPAND, None
    """don't compress zeros"""
    PAD_HEXTETS       = 'p', None, _PadMode.PAD
    """pad all hextets to 4 digits"""
    TRIM_HEXTETS      = 't', None, _PadMode.TRIM
    """trim leading zeros from hextets"""

def _parse_format_spec(spec: str, /, *, default_compress: _CompressMode = _CompressMode.COMPRESS, default_pad: _PadMode = _PadMode.TRIM) -> tuple[_CompressMode, _PadMode]:
    # TODO raise error if was already set?
    compress: _CompressMode | None = None
    pad: _PadMode | None = None
    for char in spec:
        opt: _AddressFormatSpecOption = _AddressFormatSpecOption(char)  # type: ignore  # (it's actually a __call__ to the metaclass or whatever but mypy thinks it's calling __new__)
        if opt.compress is not None:
            compress = opt.compress
        if opt.pad is not None:
            pad = opt.pad
    if compress is None:
        compress = default_compress
    if pad is None:
        pad = default_pad
    return compress, pad

class Address:
    __slots__ = '_addr',
    _addr: int

    def __init__(self, addr: int | str, /) -> None:
        match addr:
            case int():
                # TODO range check
                self._addr = addr
            case str():
                self._addr = _parse_address(addr, allow_prefix=False)
            case _ as unreachable:
                assert_never(unreachable)
        if not _MIN_IPV6_ADDR_VAL <= self._addr <= _MAX_IPV6_ADDR_VAL:
            raise ValueError('address out of range')

    def __eq__(self, other: object, /) -> bool:
        match other:
            case Address(_addr=other_addr):
                return self._addr == other_addr
            case _:
                return False

    def __add__(self, other: int, /) -> 'Address':
        match other:
            case int():
                return Address(self._addr + other)
            case _ as unreachable:
                assert_never(unreachable)

    # (__radd__ intentionally not implemented)

    def __sub__(self, other: int, /) -> 'Address':
        match other:
            case int():
                return Address(self._addr - other)
            case _ as unreachable:
                assert_never(unreachable)

    # (__rsub__ intentionally not implemented)

    def __int__(self, /) -> int:
        return self._addr

    def str_long(self, /) -> str:
        return ':'.join(f'{(self._addr >> ofs) & 0xFFFF:04x}' for ofs in range(7*16, -1, -16))

    def str_short(self, /) -> str:
        return self.str_long()  # TODO

    def __str__(self, /) -> str:
        return self.str_short()

    def __repr__(self, /) -> str:
        return f'Address({self.str_short()!r})'

    def __format__(self, format_spec: str, /) -> str:
        return f'{format_spec=}'

class Network:
    __slots__ = '_addr', '_prefix_len'
    _addr: Address
    _prefix_len: int

    @overload
    def __init__(self, addr: str) -> None: ...
    @overload
    def __init__(self, addr: str | int | Address, prefix_len: int) -> None: ...
    def __init__(self, addr: str | int | Address, prefix_len: int | _DEFAULT_T = _DEFAULT) -> None:
        match prefix_len:
            case _DEFAULT_T():
                match addr:
                    case str() as s:
                        a, self._prefix_len = _parse_address(s, allow_prefix=True, require_prefix=True)
                        self._addr = Address(a)
                    case _:
                        raise ValueError('prefix_len required but not provided')
            case int() as p:
                self._prefix_len = p
                match addr:
                    case str() | int():
                        self._addr = Address(addr)
                    case Address():
                        self._addr = addr
                    case _ as unreachable:
                        assert_never(unreachable)
            case _ as unreachable:
                assert_never(unreachable)

    @property  # TODO cache (or just compute once in init)
    def prefix_mask(self) -> int:
        return ((1 << 128) - 1) ^ ((1 << self._prefix_len) - 1)

    @property
    def prefix_len(self) -> int:
        return self._prefix_len

    @property
    def base_address(self) -> Address:
        return self._addr

    @property
    def _max_idx(self) -> int:
        return (1 << (128 - self._prefix_len)) - 1

    @overload
    def __getitem__(self, k: int, /) -> Address: ...
    @overload
    def __getitem__(self, k: slice, /) -> '_NetworkIterable': ...
    def __getitem__(self, k: int | slice, /) -> Union[Address, '_NetworkIterable']:
        match k:
            case int():
                if 0 < k < self._max_idx:
                    raise IndexError()
                return self.base_address + k
            case slice():
                return _NetworkIterable(self, k)
            case _ as unreachable:
                assert_never(unreachable)

class _NetworkIterable(Iterable[Address]):
    __slots__ = '_net', '_slice'
    _net: Network
    _slice: slice

    def __init__(self, net: Network, slice: slice) -> None:
        self._net = net
        self._slice = slice

    def __iter__(self) -> '_NetworkIterator':
        match self._slice.start:
            case int():
                start = self._slice.start + int(self._net.base_address)
            case Address():
                start = int(self._slice.start)
            case None:
                start = int(self._net.base_address)
            case _ as unexpected:
                raise TypeError(unexpected)
        match self._slice.stop:
            case int():
                stop = self._slice.stop + int(self._net.base_address)
            case Address():
                stop = int(self._slice.stop)
            case None:
                stop = int(self._net.base_address) + self._net._max_idx
            case _ as unexpected:
                raise TypeError(unexpected)
        match self._slice.step:
            case int():
                step = self._slice.step
            case None:
                step = 1
            case _ as unexpected:
                raise TypeError(unexpected)
        if step == 0:
            raise Exception('step cannot be 0')
        if step < 0:
            start, stop = stop - 1, start - 1
        return _NetworkIterator(start, stop, step)

class _NetworkIterator(Iterator[Address]):
    __slots__ = '_cur', '_start', '_stop', '_step'
    _cur: int
    _start: int
    _stop: int
    _step: int

    def __init__(self, start: int, stop: int, step: int):
        self._cur = start
        self._stop = stop
        self._step = step
        self._cur = start

    def __iter__(self) -> '_NetworkIterator':
        return self

    def __next__(self) -> Address:
        ret = self._cur
        if ret >= self._stop:
            raise StopIteration()
        self._cur += self._step
        return Address(ret)
