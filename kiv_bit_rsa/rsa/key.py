"""RSA public key, private key and key pair.
"""
import math
from abc import ABC


class Key(ABC):
    """Base class for RSA keys."""

    def __init__(self,
                 exp: int,
                 mod: int):
        """Initialize RSA key.

        :param exp: The key exponent.
        :param mod: The key modulus.
        """
        self._exp = exp
        self._mod = mod

    @property
    def exp(self) -> int:
        """Get the key exponent.
        :return: The key exponent.
        """
        return self._exp

    @property
    def mod(self) -> int:
        """Get the key modulus.
        :return: The key modulus.
        """
        return self._mod

    def byte_size(self) -> int:
        """Get the number of the required bytes to store
        the key modulus.

        :return: The number of bytes.
        """
        return math.ceil(self._mod.bit_length() / 8)

    def encrypt(self,
                num: int) -> int:
        """Encrypt integer `num`.

        RSA can only encrypt a number smaller than the key (num < key.mod).

        :param num: The number to be encrypted.
        :raise OverflowError: When integer is to big for encryption.
        :return: Encrypted `num`.
        """

        if num >= self._mod:
            raise OverflowError("Integer {} is too big for encryption".format(num))

        return pow(num, self._exp, self._mod)

    def decrypt(self,
                num: int) -> int:
        """Decrypt integer `num`.

        RSA can only decrypt a number smaller than the key (num < key.mod).

        :param num: The number to be decrypted.
        :raise OverflowError: When integer is to big for decryption.
        :return: Decrypted `num`.
        """

        if num >= self._mod:
            raise OverflowError("Integer {} is too big for decryption".format(num))

        return pow(num, self._exp, self._mod)


class PublicKey(Key):
    """RSA public key."""


class PrivateKey(Key):
    """RSA private key."""


class KeyPair:
    """Pair consisting of RSA private key and public key."""

    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        """Initialize key pair.

        :param private_key: The private key.
        :param public_key: The public key.
        """
        self._private_key = private_key
        self._public_key = public_key

    @property
    def private_key(self) -> PrivateKey:
        """Get the private key.

        :return: The private key.
        """
        return self._private_key

    @property
    def public_key(self) -> PublicKey:
        """Get the public key.

        :return: The public key.
        """
        return self._public_key
