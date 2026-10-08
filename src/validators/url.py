"""URL."""
from functools import lru_cache
import re
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote, urlsplit
from .hostname import hostname
from .utils import validator

@lru_cache
def _username_regex():
    """Compile and cache the userinfo regex."""
    # RFC 3986 userinfo = unreserved / sub-delims / ":" / pct-encoded. The
    # segment is matched as written: percent escapes are decoded only after
    # validation, so "%40" here stays two literal characters.
    return re.compile(r"^[a-zA-Z0-9\-._~!$&'()*+,;=:%]*$")

@lru_cache
def _path_regex():
    """Compile and cache the path/query/fragment regex."""
    # Single and double quotes are excluded on purpose: they are the characters
    # an unescaped reflection of user input most often smuggles into a link.
    non_ascii = (
        f"{chr(0x80)}-{chr(0xD7FF)}{chr(0xE000)}-{chr(0xFFEF)}"
        f"{chr(0x10000)}-{chr(0x10FFFF)}"
    )
    return re.compile(rf"^[a-zA-Z0-9\-._~%!$&()*+,;=:@/\[{non_ascii}]*$")

_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})

def _validate_scheme(value: str):
    """Validate scheme."""
    # urlsplit() happily treats any "letters:" prefix as a scheme, so a
    # whitelist is what keeps h://, htp:// and rdar:// out.
    return value.lower() in _SCHEMES

def _confirm_ipv6_skip(value: str, skip_ipv6_addr: bool):
    """Confirm skip IPv6 check."""
    # Bracketed hosts are the only way an IPv6 literal can reach the netloc.
    return not (skip_ipv6_addr and value.startswith("["))

def _validate_auth_segment(value: str):
    """Validate authentication segment."""
    return bool(_username_regex().match(value))

def _validate_netloc(value: str, skip_ipv6_addr: bool, skip_ipv4_addr: bool, may_have_port: bool, simple_host: bool, consider_tld: bool, private: Optional[bool], rfc_1034: bool, rfc_2782: bool):
    """Validate netloc."""
    if not value:
        return False
    auth, at, host = value.rpartition("@")
    if at and not _validate_auth_segment(auth):
        return False
    return bool(
        hostname(
            host,
            skip_ipv6_addr=skip_ipv6_addr,
            skip_ipv4_addr=skip_ipv4_addr,
            may_have_port=may_have_port,
            maybe_simple=simple_host,
            consider_tld=consider_tld,
            private=private,
            rfc_1034=rfc_1034,
            rfc_2782=rfc_2782,
        )
    )

def _validate_optionals(path: str, query: str, fragment: str, strict_query: bool):
    """Validate path query and fragments."""
    if path and not _path_regex().match(path):
        return False
    if query:
        try:
            parse_qs(query, strict_parsing=strict_query)
        except ValueError:
            return False
    if fragment and not _path_regex().match(fragment):
        return False
    return True

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
    if not isinstance(value, str) or not value:
        return False

    try:
        scheme, netloc, path, query, fragment = urlsplit(value)
    except ValueError:
        # An unbalanced IPv6 literal such as "http://[::1" is rejected here.
        return False

    if not scheme or not validate_scheme(scheme):
        return False
    if not netloc:
        return False
    if not _confirm_ipv6_skip(netloc, skip_ipv6_addr):
        return False
    if not _validate_netloc(
        netloc,
        skip_ipv6_addr,
        skip_ipv4_addr,
        may_have_port,
        simple_host,
        consider_tld,
        private,
        rfc_1034,
        rfc_2782,
    ):
        return False
    return _validate_optionals(path, query, fragment, strict_query)
