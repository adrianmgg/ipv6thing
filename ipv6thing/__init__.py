from enum import Enum, unique as enum_unique
import re
import typing
from typing import Literal, assert_never, overload

_ADDR_TOKEN_PATTERN = re.compile(r"""
(?P<num>[0-9a-zA-Z]+)
|(?P<skip>::)
|(?P<sep>:)
|(?:/(?P<prefixlen>[0-9]+))
""", re.VERBOSE)

@enum_unique
class _AddrToken(Enum):
    NUM = 'num'
    SKIP = 'skip'
    SEP = 'sep'
    PREFIX_LEN = 'prefixlen'
assert set(a.value for a in _AddrToken) == set(_ADDR_TOKEN_PATTERN.groupindex.keys())

@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[False] = False) -> int: ...
@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[True], require_prefix: Literal[True]) -> tuple[int, int]: ...
@overload
def _parse_address(addr: str, /, *, allow_prefix: Literal[True], require_prefix: bool = False) -> tuple[int, int | None]: ...
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
                    raise ValueError("address can only have one '::'")  # todo show offending token in context
                did_skip = True
            case _AddrToken.SEP:
                pass
            case _AddrToken.PREFIX_LEN:
                raise NotImplementedError()  # TODO
            case _ as unreachable:
                assert_never(unreachable)
        str_pos = match.end()
    if require_prefix and prefix_len is None:
        raise ValueError('no prefix length specified')
    if allow_prefix:
        return (lo | hi), prefix_len
    else:
        return lo | hi

class IPV6Address:
    __slots__ = '_addr',
    _addr: int

    def __init__(self, addr: int | str, /) -> None:
        match addr:
            case int():
                self._addr = addr
            case str():
                self._addr = _parse_address(addr, allow_prefix=False)
            case _ as unreachable:
                assert_never(unreachable)

    def __eq__(self, other: object, /) -> bool:
        match other:
            case IPV6Address(_addr=other_addr):
                return self._addr == other_addr
            case _:
                return False

