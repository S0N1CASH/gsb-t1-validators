"""Domain."""
from os import environ
from pathlib import Path
import re
from typing import Optional, Set
from .utils import validator

class _IanaTLD:
    """Read IANA TLDs, and optionally cache them."""
    _full_cache: Optional[Set[str]] = None
    _popular_cache = {'COM', 'ORG', 'RU', 'DE', 'NET', 'BR', 'UK', 'JP', 'FR', 'IT'}
    _popular_cache.add('ONION')

    @classmethod
    def _retrieve(cls):
        """本函数体在基线里被有意移除，请按题面要求重新实现。"""
        raise NotImplementedError()

    @classmethod
    def check(cls, tld: str):
        """本函数体在基线里被有意移除，请按题面要求重新实现。"""
        raise NotImplementedError()

@validator
def domain(value: str, /, *, consider_tld: bool=False, rfc_1034: bool=False, rfc_2782: bool=False):
    """Return whether or not given value is a valid domain.

    Examples:
        >>> domain('example.com')
        True
        >>> domain('example.com/')
        ValidationError(func=domain, args={'value': 'example.com/'})
        >>> # Supports IDN domains as well::
        >>> domain('xn----gtbspbbmkef.xn--p1ai')
        True

    Args:
        value:
            Domain string to validate.
        consider_tld:
            Restrict domain to TLDs allowed by IANA.
        rfc_1034:
            Allows optional trailing dot in the domain name.
            Ref: [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034).
        rfc_2782:
            Domain name is of type service record.
            Allows optional underscores in the domain name.
            Ref: [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782).


    Returns:
        (Literal[True]): If `value` is a valid domain name.
        (ValidationError): If `value` is an invalid domain name.

    Raises:
        (UnicodeError): If `value` cannot be encoded into `idna` or decoded into `utf-8`.
    """
    raise NotImplementedError()
