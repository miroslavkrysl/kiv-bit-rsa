"""RSA public and private keys"""

from abc import ABC

from tomlkit import dumps
from tomlkit import parse, document, table
from tomlkit.exceptions import TOMLKitError


class KeyFileError(Exception):
    """Bad RSA key file"""


class Key(ABC):
    """Base class for RSA keys."""

    __slots__ = ['_exp', '_mod']

    _key_types = ['public', 'private']

    def __init__(self, exp, mod):
        self._exp = exp
        self._mod = mod

    def to_toml(self):
        """Dumps the key to a TOML string.

        :return: The string in TOML format.
        """

        doc = document()

        impl = table()
        impl.add("name", "mkrsa")

        if isinstance(self, PublicKey):
            t = "public"
        else:
            t = "private"

        key = table()
        key.add("type", t)
        key.add("exp", self.exp)
        key.add("mod", self.mod)

        doc.add("implementation", impl)
        doc.add("key", key)

        return dumps(doc)

    @classmethod
    def from_toml(cls, string):
        """Load the key from TOML string.

        :param string: The string in TOML format.
        """

        try:
            doc = parse(string)

            impl = doc['implementation']

            if impl['name'] != 'mkrsa':
                raise Exception()

            key = doc['key']

            if key['type'] not in cls._key_types:
                raise Exception()

            if key['type'] == 'public':
                return PublicKey(key['exp'], key['mod'])
            else:
                return PrivateKey(key['exp'], key['mod'])

        except TOMLKitError:
            raise KeyFileError('Key TOML string is in bad format.')

    @property
    def exp(self):
        return self._exp

    @property
    def mod(self):
        return self._mod


class PublicKey(Key):
    """RSA public key."""


class PrivateKey(Key):
    """RSA private key."""
