from collections.abc import Iterable
from typing import Iterator, overload

class Address:
    def __init__(self, addr: int | str, /) -> None: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __add__(self, other: int, /) -> Address: ...
    def __sub__(self, other: int, /) -> Address: ...
    def __and__(self, other: int, /) -> Address: ...
    def __or__(self, other: int, /) -> Address: ...
    def __int__(self, /) -> int: ...
    def __format__(self, format_spec: str, /) -> str: ...
    def __str__(self, /) -> str: ...
    def __repr__(self, /) -> str: ...

class Network:
    @overload
    def __init__(self, addr: str) -> None: ...
    @overload
    def __init__(self, addr: str | int | Address, prefix_len: int) -> None: ...
    @property
    def prefix_mask(self) -> int: ...
    @property
    def prefix_len(self) -> int: ...
    @property
    def base_address(self) -> Address: ...
    @overload
    def __getitem__(self, k: int, /) -> Address: ...
    @overload
    def __getitem__(self, k: slice, /) -> Iterable[Address]: ...
    def __contains__(self, addr: Address, /) -> bool: ...
    def __iter__(self) -> Iterator[Address]: ...
    @property
    def num_addresses(self) -> int: ...
    def __format__(self, format_spec: str, /) -> str: ...
    def __str__(self, /) -> str: ...
    def __repr__(self, /) -> str: ...
