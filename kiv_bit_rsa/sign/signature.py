"""Definition of signature."""

from __future__ import annotations

from typing import Type
from kiv_bit_rsa.hash import Hash
from kiv_bit_rsa.rsa import Key, Rsa
from kiv_bit_rsa.sign.signable import Signable


class Signature:
    """An object signature.

    :py:class:`Signature` holds the signed hash (with an RSA
    cipher encryption key) and info about the hash algorithm.
    """

    def __init__(self,
                 hash_class: Type[Hash],
                 digest_cipher: bytes):
        """Initialize a signature of an object.

        :param hash_class: The class used for hash.
        :param digest_cipher: Encrypted hash digest.
        """
        self._hash_class = hash_class
        self._digest_cipher = digest_cipher

    @classmethod
    def sign(cls,
             signable: Signable,
             hash_class: Type[Hash],
             key: Key) -> Signature:
        """Create a signature of object `signable`.

        :param signable: The signable object to sign.
        :param hash_class: The class used for hash.
        :param key: The encryption key.
        :return: The signature of object `signable`.
        """

        h = signable.hash(hash_class)
        digest_cipher = Rsa().encrypt(h.to_bytes(), key)

        return Signature(hash_class, digest_cipher)

    def verify(self,
               signable: Signable,
               key: Key) -> bool:
        """Verify the signable object against this signature.

        :param key: The decryption key.
        :param signable: The signable object to verify.
        :return: True if the contents of the file match the signature.
        """

        h = signable.hash(self._hash_class)
        digest = Rsa().decrypt(self._digest_cipher, key)

        return digest == h.to_bytes()

    @property
    def hash_method(self):
        """Get the hash method."""
        return self._hash_class

    @property
    def hash_cipher(self):
        """Get the hash cipher"""
        return self._digest_cipher
