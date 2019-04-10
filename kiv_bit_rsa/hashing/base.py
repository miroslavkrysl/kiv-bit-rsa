"""Base class for hashing methods.

Every hashing method should inherit from the class :py:class:`kiv_bit_rsa.hashing.HashingMethod`.
"""

from abc import ABC, abstractmethod


class HashingMethod(ABC):

    @classmethod
    @abstractmethod
    def block_size(cls):
        """Get size of the method's data block.

        Get the size if the bytes block that is processed
        during one round of the method. It could by 1 byte
        and more or 0 if the data is processed whole at once.

        :return: Size of the block in bytes.
        """

    @abstractmethod
    def update(self, data):
        """Update the hash object.

        :param data: The data to update the hash.
        """

    @abstractmethod
    def digest(self):
        """Get the hash object digest as bytes.

        :return: The bytes of size 32 representing the digest.
        """

    @abstractmethod
    def hex_digest(self):
        """Get the hash object digest as a hex string.

        :return: The hexadecimal number as a string of size 32 representing the digest.
        """
