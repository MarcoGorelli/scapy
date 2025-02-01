# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Direct Access dictionary.
"""

from __future__ import annotations
from scapy.error import Scapy_Exception
from scapy.compat import plain_str

# Typing
from typing import (
    Any,
    Dict,
    Generic,
    Iterator,
    List,
    Tuple,
    Type,
    TypeVar,
    Union,
)
from scapy.compat import Self


###############################
#  Direct Access dictionary   #
###############################


def fixname(x: Union[bytes, str]) -> str:
    """
    Modifies a string to make sure it can be used as an attribute name.
    """
    x = plain_str(x)
    if x and str(x[0]) in "0123456789":
        x = "n_" + x
    return x.translate(
        "________________________________________________"
        "0123456789_______ABCDEFGHIJKLMNOPQRSTUVWXYZ______"
        "abcdefghijklmnopqrstuvwxyz____________________________"
        "______________________________________________________"
        "___________________________________________________"
    )


class DADict_Exception(Scapy_Exception):
    pass


_K = TypeVar('_K')  # Key type
_V = TypeVar('_V')  # Value type


class DADict(Generic[_K, _V]):
    """
    Direct Access Dictionary

    This acts like a dict, but it provides a direct attribute access
    to its keys through its values. This is used to store protocols,
    manuf...

    For instance, scapy fields will use a DADict as an enum::

        ETHER_TYPES[2048] -> IPv4

    Whereas humans can access::

        ETHER_TYPES.IPv4 -> 2048
    """
    __slots__ = ["_name", "d"]

    def __init__(self, _name: str = "DADict", **kargs: Any) -> None:
        self._name = _name
        self.d: Dict[_K, _V] = {}
        self.update(kargs)  # type: ignore

    def ident(self, v: _V) -> str:
        """
        Return value that is used as key for the direct access
        """
        if isinstance(v, (str, bytes)):
            return fixname(v)
        return "unknown"

    def update(self, *args: Dict[_K, _V], **kwargs: Dict[_K, _V]) -> None:
        for k, v in dict(*args, **kwargs).items():
            self[k] = v  # type: ignore

    def iterkeys(self) -> Iterator[_K]:
        for x in self.d:
            if not isinstance(x, str) or x[0] != "_":
                yield x

    def keys(self) -> List[_K]:
        return list(self.iterkeys())

    def __iter__(self) -> Iterator[_K]:
        return self.iterkeys()

    def itervalues(self) -> Iterator[_V]:
        return self.d.values()  # type: ignore

    def values(self) -> List[_V]:
        return list(self.itervalues())

    def _show(self) -> None:
        for k in self.iterkeys():
            print("%10s = %r" % (k, self[k]))

    def __repr__(self) -> str:
        return "<%s - %s elements>" % (self._name, len(self))

    def __getitem__(self, attr: _K) -> _V:
        return self.d[attr]

    def __setitem__(self, attr: _K, val: _V) -> None:
        self.d[attr] = val

    def __len__(self) -> int:
        return len(self.d)

    def __nonzero__(self) -> bool:
        # Always has at least its name
        return len(self) > 1
    __bool__ = __nonzero__

    def __getattr__(self, attr: str) -> _K:
        try:
            return object.__getattribute__(self, attr)  # type: ignore
        except AttributeError:
            for k, v in self.d.items():
                if self.ident(v) == attr:
                    return k
        raise AttributeError

    def __dir__(self) -> List[str]:
        return [self.ident(x) for x in self.itervalues()]

    def __reduce__(self) -> Tuple[Type[Self], Tuple[str], Tuple[Dict[_K, _V]]]:
        return (self.__class__, (self._name,), (self.d,))

    def __setstate__(self, state: Tuple[Dict[_K, _V]]) -> Self:
        self.d.update(state[0])
        return self
