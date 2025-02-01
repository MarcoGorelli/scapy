# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Resolve Autonomous Systems (AS).
"""


from __future__ import annotations

import socket
from scapy.config import conf
from scapy.compat import plain_str

from typing import (
    Any,
    Optional,
    Tuple,
    List,
)


class AS_resolver:
    server = None
    options: Optional[str] = "-k"

    def __init__(self, server: Optional[str] = None, port: int = 43, options: Optional[str] = None) -> None:
        if server is not None:
            self.server = server
        self.port = port
        if options is not None:
            self.options = options

    def _start(self) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server, self.port))
        if self.options:
            self.s.send(self.options.encode("utf8") + b"\n")
            self.s.recv(8192)

    def _stop(self) -> None:
        self.s.close()

    def _parse_whois(self, txt: bytes) -> Tuple[Optional[str], str]:
        asn, desc = None, b""
        for line in txt.splitlines():
            if not asn and line.startswith(b"origin:"):
                asn = plain_str(line[7:].strip())
            if line.startswith(b"descr:"):
                if desc:
                    desc += b"\n"
                desc += line[6:].strip()
            if asn is not None and desc:
                break
        return asn, plain_str(desc.strip())

    def _resolve_one(self, ip: str) -> Tuple[str, Optional[str], str]:
        self.s.send(("%s\n" % ip).encode("utf8"))
        x = b""
        while not (b"%" in x or b"source" in x):
            d = self.s.recv(8192)
            if not d:
                break
            x += d
        asn, desc = self._parse_whois(x)
        return ip, asn, desc

    def resolve(self,
                *ips: str
                ) -> List[Tuple[str, Optional[str], str]]:
        self._start()
        ret: List[Tuple[str, Optional[str], str]] = []
        for ip in ips:
            ip, asn, desc = self._resolve_one(ip)
            if asn is not None:
                ret.append((ip, asn, desc))
        self._stop()
        return ret


class AS_resolver_riswhois(AS_resolver):
    server = "riswhois.ripe.net"
    options = "-k -M -1"


class AS_resolver_radb(AS_resolver):
    server = "whois.ra.net"
    options = "-k -M"


class AS_resolver_cymru(AS_resolver):
    server = "whois.cymru.com"
    options = None

    def resolve(self,
                *ips: str
                ) -> List[Tuple[str, Optional[str], str]]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.server, self.port))
        s.send(
            b"begin\r\n" +
            b"\r\n".join(ip.encode() for ip in ips) +
            b"\r\nend\r\n"
        )
        r = b""
        while True:
            line = s.recv(8192)
            if line == b"":
                break
            r += line
        s.close()

        return self.parse(r)

    def parse(self, data: bytes) -> List[Tuple[str, Optional[str], str]]:
        """Parse bulk cymru data"""

        ASNlist: List[Tuple[str, Optional[str], str]] = []
        for line in plain_str(data).splitlines()[1:]:
            if "|" not in line:
                continue
            asn, ip, desc = [elt.strip() for elt in line.split('|')]
            if asn == "NA":
                continue
            asn = "AS%s" % asn
            ASNlist.append((ip, asn, desc))
        return ASNlist


class AS_resolver_multi(AS_resolver):
    def __init__(self, *reslist: AS_resolver) -> None:
        AS_resolver.__init__(self)
        if reslist:
            self.resolvers_list = reslist
        else:
            self.resolvers_list = (AS_resolver_radb(),
                                   AS_resolver_cymru())

    def resolve(self, *ips: Any) -> List[Tuple[str, Optional[str], str]]:
        todo = ips
        ret = []
        for ASres in self.resolvers_list:
            try:
                res = ASres.resolve(*todo)
            except socket.error:
                continue
            todo = tuple(ip for ip in todo if ip not in [r[0] for r in res])
            ret += res
            if not todo:
                break
        return ret


conf.AS_resolver = AS_resolver_multi()
