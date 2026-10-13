"""Hostname."""
from functools import lru_cache
import re
from typing import Optional
from .domain import domain
from .ip_address import ipv4, ipv6
from .utils import validator

@lru_cache
def _port_regex():
    """Port validation regex."""
    return re.compile(
        r"^(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}"
        r"|[1-5][0-9]{4}|[1-9][0-9]{0,3})$"
    )

@lru_cache
def _simple_hostname_regex():
    """Simple hostname validation regex."""
    return re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

def _port_validator(value: str):
    """Returns host segment if port is valid."""
    if value.count(":") != 1:
        return False
    host, _, port = value.partition(":")
    if _port_regex().match(port):
        return host
    return False

@validator
def hostname(value: str, /, *, skip_ipv6_addr: bool=False, skip_ipv4_addr: bool=False, may_have_port: bool=True, maybe_simple: bool=True, consider_tld: bool=False, private: Optional[bool]=None, rfc_1034: bool=False, rfc_2782: bool=False):
    """Return whether or not given value is a valid hostname.

    Examples:
        >>> hostname("ubuntu-pc:443")
        True
        >>> hostname("this-pc")
        True
        >>> hostname("xn----gtbspbbmkef.xn--p1ai:65535")
        True
        >>> hostname("_example.com")
        ValidationError(func=hostname, args={'value': '_example.com'})
        >>> hostname("123.5.77.88:31000")
        True
        >>> hostname("12.12.12.12")
        True
        >>> hostname("[::1]:22")
        True
        >>> hostname("dead:beef:0:0:0:0000:42:1")
        True
        >>> hostname("[0:0:0:0:0:ffff:1.2.3.4]:-65538")
        ValidationError(func=hostname, args={'value': '[0:0:0:0:0:ffff:1.2.3.4]:-65538'})
        >>> hostname("[0:&:b:c:@:e:f::]:9999")
        ValidationError(func=hostname, args={'value': '[0:&:b:c:@:e:f::]:9999'})

    Args:
        value:
            Hostname string to validate.
        skip_ipv6_addr:
            When hostname string cannot be an IPv6 address.
        skip_ipv4_addr:
            When hostname string cannot be an IPv4 address.
        may_have_port:
            Hostname string may contain port number.
        maybe_simple:
            Hostname string maybe only hyphens and alpha-numerals.
        consider_tld:
            Restrict domain to TLDs allowed by IANA.
        private:
            Embedded IP address is public if `False`, private/local if `True`.
        rfc_1034:
            Allow trailing dot in domain/host name.
            Ref: [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034).
        rfc_2782:
            Domain/Host name is of type service record.
            Ref: [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782).

    Returns:
        (Literal[True]): If `value` is a valid hostname.
        (ValidationError): If `value` is an invalid hostname.
    """
    if not value:
        return False

    # bracketed IPv6 address, optionally followed by a port
    if value.startswith("["):
        if skip_ipv6_addr:
            return False
        closing = value.find("]")
        if closing == -1:
            return False
        address = value[1:closing]
        remainder = value[closing + 1 :]
        if remainder:
            if not (may_have_port and remainder.startswith(":")):
                return False
            if not _port_regex().match(remainder[1:]):
                return False
        return bool(ipv6(address, cidr=False))

    # bare IPv6 address
    if value.count(":") >= 2:
        if skip_ipv6_addr:
            return False
        return bool(ipv6(value, cidr=False))

    # host, optionally followed by a port
    host = value
    if ":" in value:
        if not may_have_port:
            return False
        host = _port_validator(value)
        if not host:
            return False

    if not host:
        return False

    if not skip_ipv4_addr and ipv4(host, cidr=False, private=private):
        return True

    if maybe_simple and _simple_hostname_regex().match(host):
        return True

    return bool(
        domain(host, consider_tld=consider_tld, rfc_1034=rfc_1034, rfc_2782=rfc_2782)
    )
