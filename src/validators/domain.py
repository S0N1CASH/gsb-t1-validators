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
        """Read TLDs from local IANA file."""
        tld_file = environ.get("VALIDATORS_TLD_FILE")
        path = Path(tld_file) if tld_file else Path(__file__).parent / "_tld.txt"
        return {
            line.strip().upper()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }

    @classmethod
    def check(cls, tld: str):
        """Check whether given TLD is registered with IANA."""
        tld = tld.upper()
        if tld in cls._popular_cache:
            return True
        if cls._full_cache is None:
            cls._full_cache = cls._retrieve()
        return tld in cls._full_cache


_LABEL_REGEX = re.compile(r"^[A-Za-z0-9_-]*$")


def _label_is_valid(label: str, rfc_2782: bool = False, is_tld: bool = False):
    """Return whether or not given label is valid."""
    if not label or len(label) > 63 or not _LABEL_REGEX.match(label):
        return False

    # underscores are only allowed for service records, and never in a TLD
    if "_" in label and (not rfc_2782 or is_tld or "__" in label):
        return False

    core = label.strip("_") if rfc_2782 and not is_tld else label
    if not core or core.startswith("-") or core.endswith("-"):
        return False

    return True

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
    if not value or len(value) > 253:
        return False

    if value.endswith("."):
        if not rfc_1034:
            return False
        value = value[:-1]

    if not value:
        return False

    # internationalized domain names are validated in their ASCII (punycode) form
    if not value.isascii():
        value = value.encode("idna").decode("ascii")

    if value.startswith(".") or value.endswith("."):
        return False

    labels = value.split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit() or not _label_is_valid(tld, is_tld=True):
        return False

    if consider_tld and not _IanaTLD.check(tld):
        return False

    return all(_label_is_valid(label, rfc_2782=rfc_2782) for label in labels[:-1])
