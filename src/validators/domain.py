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
        """Return the set of TLDs listed in the bundled IANA data file."""
        path = Path(
            environ.get("VALIDATORS_TLD_FILE", str(Path(__file__).parent / "_tld.txt"))
        )
        with open(path, encoding="utf-8") as tld_file:
            return {
                line.strip().upper()
                for line in tld_file
                if line.strip() and not line.startswith("#")
            }

    @classmethod
    def check(cls, tld: str):
        """Return whether `tld` is a known top level domain."""
        if not tld:
            return False
        tld = tld.upper()
        if tld in cls._popular_cache:
            return True
        if cls._full_cache is None:
            try:
                cls._full_cache = cls._retrieve()
            except OSError:
                cls._full_cache = set()
        return tld in cls._full_cache


_LABEL_CHARS = "0-9A-Za-z\u00a1-\ufffc\U00010000-\U0010ffff"
_LABEL_CORE = "[{0}](?:[{0}\\-]{{0,61}}[{0}])?".format(_LABEL_CHARS)
_LABEL_RE = re.compile("^{}$".format(_LABEL_CORE))
_LABEL_RFC_2782_RE = re.compile("^_?{0}(?:_(?:{0}))*_?$".format(_LABEL_CORE))
_TLD_LETTER_RE = re.compile(r"[^\W\d_]")


def _valid_label(label: str, rfc_2782: bool):
    """Return whether `label` may appear in a domain name."""
    if not label or len(label) > 63:
        return False
    pattern = _LABEL_RFC_2782_RE if rfc_2782 else _LABEL_RE
    return bool(pattern.match(label))


def _valid_tld(tld: str):
    """Return whether `tld` is a syntactically plausible top level domain."""
    return len(tld) >= 2 and bool(_TLD_LETTER_RE.search(tld))

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
    if not value or not isinstance(value, str):
        return False

    if len(value) > 254:
        return False

    if rfc_1034 and value.endswith("."):
        value = value[:-1]

    if "." not in value:
        return False

    labels = value.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False

    if not all(_valid_label(label, rfc_2782) for label in labels):
        return False

    tld = labels[-1]
    if not _valid_tld(tld):
        return False

    if consider_tld and not _IanaTLD.check(tld):
        return False

    return True
