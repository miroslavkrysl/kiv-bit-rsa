"""RSA key formatters for converting keys to string representation"""

from abc import abstractmethod, ABC

import toml
from kiv_bit_rsa.rsa.key import Key, PublicKey, PrivateKey
from kiv_bit_rsa.exception import KivBitRsaError


class KeyFormatError(KivBitRsaError):
    """RSA key string is in wrong format"""


class KeyFormatter(ABC):
    """Base class for RSA key formatting.
    """

    @abstractmethod
    def to_string(self,
                  key: Key) -> str:
        """Convert `key` to string representation.

        :param key: The key to convert to string.
        :return: The key string representation.
        """

    @abstractmethod
    def from_string(self,
                    string: str) -> Key:
        """Parse key string representation into Key.

        :param string: The key string representation.
        :return: The Key.
        """


class TomlKeyFormatter(KeyFormatter):
    """Key formatter that uses TOML format."""

    def to_string(self, key: Key) -> str:
        """Convert `key` to string representation in TOML format.
        :param key: The key to convert to string.
        :return: The key string representation.
        """

        key_dict = {}

        if issubclass(type(key), PublicKey):
            key_dict["type"] = "public"
        elif issubclass(type(key), PrivateKey):
            key_dict["type"] = "private"
        else:
            raise NotImplementedError("Can not format object of type: {}".format(type(key)))

        key_dict["exp"] = key.exp
        key_dict["mod"] = key.mod

        doc = {"rsa-key": key_dict}

        return toml.dumps(doc)

    def from_string(self, string: str) -> Key:
        """Parse key string representation
        in TOML format into Key.

        :param string: The key string representation.
        :return: The Key.
        """

        try:
            doc = toml.loads(string)

            key = doc['rsa-key']

            if key['type'] not in {'public', 'private'}:
                raise Exception()

            if not isinstance(key['exp'], int):
                raise Exception()

            if not isinstance(key['mod'], int):
                raise Exception()

            if key['type'] == 'public':
                return PublicKey(key['exp'], key['mod'])
            else:
                return PrivateKey(key['exp'], key['mod'])

        except ...:
            raise KeyFormatError('Key TOML string is in bad format.')

