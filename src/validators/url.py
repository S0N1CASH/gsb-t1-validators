"""URL."""
from functools import lru_cache
import re
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote, urlsplit
from .hostname import hostname
from .utils import validator

@lru_cache
def _username_regex():
    """本函数体在基线里被有意移除，请按题面要求重新实现。"""
    raise NotImplementedError()

@lru_cache
def _path_regex():
    """本函数体在基线里被有意移除，请按题面要求重新实现。"""
    raise NotImplementedError()

def _validate_scheme(value: str):
    """Validate scheme."""
    raise NotImplementedError()

def _confirm_ipv6_skip(value: str, skip_ipv6_addr: bool):
    """Confirm skip IPv6 check."""
    raise NotImplementedError()

def _validate_auth_segment(value: str):
    """Validate authentication segment."""
    raise NotImplementedError()

def _validate_netloc(value: str, skip_ipv6_addr: bool, skip_ipv4_addr: bool, may_have_port: bool, simple_host: bool, consider_tld: bool, private: Optional[bool], rfc_1034: bool, rfc_2782: bool):
    """Validate netloc."""
    raise NotImplementedError()

def _validate_optionals(path: str, query: str, fragment: str, strict_query: bool):
    """Validate path query and fragments."""
    raise NotImplementedError()

@validator
def url(value: str, /, *, skip_ipv6_addr: bool=False, skip_ipv4_addr: bool=False, may_have_port: bool=True, simple_host: bool=False, strict_query: bool=True, consider_tld: bool=False, private: Optional[bool]=None, rfc_1034: bool=False, rfc_2782: bool=False, validate_scheme: Callable[[str], bool]=_validate_scheme):
    """Return whether or not given value is a valid URL.

    This validator was originally inspired from [URL validator of dperini][1].
    The following diagram is from [urlly][2]::


            foo://admin:hunter1@example.com:8042/over/there?name=ferret#nose
            \\_/   \\___/ \\_____/ \\_________/ \\__/\\_________/ \\_________/ \\__/
             |      |       |       |        |       |          |         |
          scheme username password hostname port    path      query    fragment

    [1]: https://gist.github.com/dperini/729294
    [2]: https://github.com/treeform/urlly

    Examples:
        >>> url('http://duck.com')
        True
        >>> url('ftp://foobar.dk')
        True
        >>> url('http://10.0.0.1')
        True
        >>> url('http://example.com/">user@example.com')
        ValidationError(func=url, args={'value': 'http://example.com/">user@example.com'})

    Args:
        value:
            URL string to validate.
        skip_ipv6_addr:
            When URL string cannot contain an IPv6 address.
        skip_ipv4_addr:
            When URL string cannot contain an IPv4 address.
        may_have_port:
            URL string may contain port number.
        simple_host:
            URL string maybe only hyphens and alpha-numerals.
        strict_query:
            Fail validation on query string parsing error.
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
        validate_scheme:
            Function that validates URL scheme.

    Returns:
        (Literal[True]): If `value` is a valid url.
        (ValidationError): If `value` is an invalid url.
    """
    raise NotImplementedError()
