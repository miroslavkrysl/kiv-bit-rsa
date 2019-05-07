"""Base class for hashes.

Every hash method should inherit from the class :py:class:`Hash`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Hash(ABC):
    """Hashing method representation.

    Class :py:class:`Hash` represents a hash method.
    Concrete implementations of any hash methods
    should inherit from this class.
    """

    @classmethod
    @abstractmethod
    def chunk_size(cls) -> int:
        """Get size of the methods data chunk.

        Get the size of the chunk of bytes that is processed
        during one round of the method. It could by 1 byte
        and more or 0 if the data is processed whole at once.

        :return: Size of the chunk in bytes.
        """

    @classmethod
    @abstractmethod
    def name(cls) -> str:
        """Get hash methods name.

        :return: The name of the hash method.
        """

    @abstractmethod
    def update(self,
               data: bytes):
        """Update the hash with `data`.

        :param data: The data to update the hash with.
        """

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Get the hash digest as bytes.

        :return: The digest as bytes.
        """

    @abstractmethod
    def to_hex(self) -> str:
        """Get the hash digest as a hex string.

        :return: The digest as a hex string.
        """
