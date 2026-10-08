"""Domain."""
from os import environ
from pathlib import Path
import re
from typing import Optional, Set
from .utils import validator

# Code points a label may be built from once the value has been lower-cased.
# Surrogate halves, U+FFFD and the unassigned tail of plane 0 are left out on
# purpose: they are never legal in an IDN label and must not be accepted just
# because they happen to fall outside ASCII.
_NON_ASCII = (
    f"{chr(0x80)}-{chr(0xD7FF)}{chr(0xE000)}-{chr(0xFFEF)}"
    f"{chr(0x10000)}-{chr(0x10FFFF)}"
)

_LABEL_REGEX = re.compile(rf"^[a-z0-9{_NON_ASCII}][a-z0-9{_NON_ASCII}-]{{0,62}}$")
_LABEL_REGEX_RFC_2782 = re.compile(rf"^[a-z0-9_{_NON_ASCII}][a-z0-9_{_NON_ASCII}-]{{0,62}}$")
# A top level label has to start with a letter.
_TLD_REGEX = re.compile(rf"^[a-z{_NON_ASCII}][a-z0-9{_NON_ASCII}-]{{0,62}}$")

class _IanaTLD:
    """Read IANA TLDs, and optionally cache them."""
    _full_cache: Optional[Set[str]] = None
    _popular_cache = {'COM', 'ORG', 'RU', 'DE', 'NET', 'BR', 'UK', 'JP', 'FR', 'IT'}
    _popular_cache.add('ONION')

    @classmethod
    def _retrieve(cls):
        """Read the IANA root list once and keep it as a set of upper-cased names."""
        if cls._full_cache is None:
            override = environ.get("VALIDATORS_TLD")
            path = Path(override) if override else Path(__file__).parent / "_tld.txt"
            with path.open(encoding="utf-8") as handle:
                cls._full_cache = {
                    line.strip().upper()
                    for line in handle
                    if line.strip() and not line.startswith("#")
                }
        return cls._full_cache

    @classmethod
    def check(cls, tld: str):
        """Return whether or not given TLD is allowed by IANA."""
        # The popular cache answers the everyday cases without touching disk.
        tld = tld.upper()
        return tld in cls._popular_cache or tld in cls._retrieve()

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
    if not isinstance(value, str) or not value or len(value) > 253:
        return False

    if value[-1] == ".":
        if not rfc_1034:
            return False
        value = value[:-1]
        if not value:
            return False

    value = value.lower()
    labels = value.split(".")
    if len(labels) < 2:
        return False

    top_level = labels[-1]
    if not _TLD_REGEX.match(top_level):
        return False
    if consider_tld and not _IanaTLD.check(top_level):
        return False

    label_regex = _LABEL_REGEX_RFC_2782 if rfc_2782 else _LABEL_REGEX
    for label in labels[:-1]:
        if not label_regex.match(label):
            return False
        if rfc_2782 and "__" in label:
            return False
    return True
