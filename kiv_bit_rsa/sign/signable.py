"""Definition of signable objects."""

from abc import ABC, abstractmethod
from typing import BinaryIO, Type

from kiv_bit_rsa.hash import Hash


class Signable(ABC):
    """Base class for signable objects."""

    @abstractmethod
    def hash(self,
             hash_class: Type[Hash]) -> Hash:
        """Get the objects hash.

        :return: The hash.
        """


class SignableBinaryIO(Signable):
    """Signable file/binary io for use with signatures.
    """

    def __init__(self,
                 file: BinaryIO):
        """Initialize a signable file/binary io.

        :param file: The input file or any binary stream to sign.
        """
        self._file = file
        self._hash = None

    def hash(self,
             hash_class: Type[Hash]) -> Hash:
        """Get the objects hash.

        :return: The hash.
        """

        if self._hash:
            return self._hash

        h = hash_class()
        block_size = h.chunk_size()

        for chunk in iter(lambda: self._file.read(block_size), b''):
            h.update(chunk)

        self._hash = h

        return h
