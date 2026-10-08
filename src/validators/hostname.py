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
    return re.compile(r"^[0-9]{1,5}$")

@lru_cache
def _simple_hostname_regex():
    """Simple hostname validation regex."""
    return re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

def _port_validator(value: str):
    """Returns host segment if port is valid."""
    host, colon, port = value.rpartition(":")
    if not colon or not _port_regex().match(port):
        return None
    return host

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
    if not isinstance(value, str) or not value:
        return False

    # An IPv6 literal is only addressable inside brackets, with an optional
    # port following the closing bracket (RFC 3986 section 3.2.2).
    if value[0] == "[":
        address, closing, rest = value.partition("]")
        if not closing:
            return False
        if rest:
            if not may_have_port or not rest.startswith(":"):
                return False
            if not _port_regex().match(rest[1:]):
                return False
        return not skip_ipv6_addr and bool(ipv6(address[1:]))

    host = value
    if ":" in value:
        if not may_have_port:
            # A colon that cannot introduce a port would have to be part of an
            # unbracketed address, which this validator does not accept.
            return False
        host = _port_validator(value)
        if not host:
            return False
        if ":" in host:
            # More than one colon left over: an IPv6 address that forgot its
            # brackets.
            return False

    if "." in host and all(part.isdigit() for part in host.split(".")):
        if skip_ipv4_addr:
            return False
        return bool(ipv4(host, private=private))

    if "." not in host:
        if not maybe_simple:
            return False
        return bool(_simple_hostname_regex().match(host.lower()))

    return bool(
        domain(
            host,
            consider_tld=consider_tld,
            rfc_1034=rfc_1034,
            rfc_2782=rfc_2782,
        )
    )
