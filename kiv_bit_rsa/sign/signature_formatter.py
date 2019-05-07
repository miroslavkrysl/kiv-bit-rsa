"""Signature formatters for converting signatures to string representation."""
import base64
from abc import abstractmethod, ABC

import toml
from kiv_bit_rsa.exception import KivBitRsaError
from kiv_bit_rsa.hash import Md5
from kiv_bit_rsa.sign import Signature


class SignatureFormatError(KivBitRsaError):
    """Signature string is in wrong format"""


class SignatureFormatter(ABC):
    """Base class for Signature formatting.
    """

    @abstractmethod
    def to_string(self,
                  signature: Signature) -> str:
        """Convert `key` to string representation.

        :param signature: The signature to convert to string.
        :return: The signature string representation.
        """

    @abstractmethod
    def from_string(self,
                    string: str) -> Signature:
        """Parse signature string representation into Signature instance.

        :param string: The signature string representation.
        :return: The Signature.
        """


class TomlSignatureFormatter(SignatureFormatter):
    """Signature formatter that uses TOML format."""

    def to_string(self, signature: Signature) -> str:
        """Convert `signature` to string representation in TOML format.
        :param signature: The signature to convert to string.
        :return: The signature string representation.
        """

        signature_dict = {}

        if signature.hash_method == Md5:
            signature_dict["hash-method"] = "MD5"
        else:
            raise NotImplementedError("Can not format hash method of type: {}".format(signature.hash_method))

        signature_dict["hash-cipher"] = base64.encodebytes(signature.hash_cipher).decode("utf8")

        doc = {"signature": signature_dict}

        return toml.dumps(doc)

    def from_string(self, string: str) -> Signature:
        """Parse signature string representation
        in TOML format into Signature instance.

        :param string: The signature string representation.
        :return: The Signature.
        """

        try:
            doc = toml.loads(string)

            signature = doc['signature']

            if signature['hash-method'] == 'MD5':
                return Signature(Md5, base64.decodebytes(signature['hash-cipher'].encode("utf8")))
            else:
                raise NotImplementedError(
                    "Can not load signature with hash method of type: {}".format(signature['hash-method']))

        except ...:
            raise SignatureFormatError('Signature TOML string is in bad format.')

