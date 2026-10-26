"""Runtime scope for local labs. No default target address or port."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class LocalScope:
    origin: str
    connection_origin: str
    hostname: str
    address: str

    @classmethod
    def from_target(cls, target: str):
        try:
            if not target or target != target.strip() or any(c.isspace() for c in target):
                raise ValueError
            parsed = urlsplit(target)
            host = parsed.hostname
            if (
                parsed.scheme not in {"http", "https"} or not host
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or "?" in target or "#" in target or "\\" in target
            ):
                raise ValueError
            port = parsed.port
            if port == 0 or parsed.netloc.endswith(":"):
                raise ValueError
            if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        except (TypeError, ValueError):
            raise ScopeError(
                "Target harus berupa origin HTTP(S) localhost atau IP loopback, "
                "tanpa path, query, kredensial, atau fragment."
            ) from None
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(
                host, port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )}
            if not addresses or not all(ipaddress.ip_address(ip).is_loopback for ip in addresses):
                raise ValueError
            address = sorted(addresses, key=lambda ip: (ipaddress.ip_address(ip).version, ip))[0]
        except (OSError, ValueError):
            raise ScopeError("Target tidak dapat di-resolve seluruhnya ke loopback.") from None
        authority = f"[{host}]" if ":" in host else host
        pinned = f"[{address}]" if ":" in address else address
        if port is not None and port != (443 if parsed.scheme == "https" else 80):
            authority += f":{port}"
            pinned += f":{port}"
        return cls(
            origin=f"{parsed.scheme}://{authority}",
            connection_origin=f"{parsed.scheme}://{pinned}", hostname=host, address=address,
        )

    def logical_url(self, url: str) -> str:
        parsed = urlsplit(url)
        pinned = urlsplit(self.connection_origin)
        if (parsed.scheme, parsed.netloc) == (pinned.scheme, pinned.netloc):
            return urlunsplit((parsed.scheme, urlsplit(self.origin).netloc,
                               parsed.path, parsed.query, parsed.fragment))
        return url

    def connection_url(self, url: str) -> str:
        parsed = urlsplit(url)
        origin = urlsplit(self.origin)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            raise ScopeError("Request berada di luar origin scope.")
        return urlunsplit((parsed.scheme, urlsplit(self.connection_origin).netloc,
                           parsed.path, parsed.query, ""))

    def browser_args(self) -> list[str]:
        args = ["--disable-background-networking", "--no-proxy-server"]
        return args

    def as_dict(self) -> dict:
        return {"origin": self.origin, "resolved_address": self.address,
                "restriction": "loopback_only", "same_origin_only": True}
