"""RSA public and private keys

"""
import math
from abc import ABC

from kiv_bit_rsa.exception import KivBitRsaError


class KeyFileError(KivBitRsaError):
    """RSA key file is in wrong format"""


class RsaKey(ABC):
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

    def encrypt_int(self,
                    num: int) -> int:
        """Encrypt integer `num`.

        RSA can only encrypt a number smaller than the key (num < key.mod).

        :param num: The number to be encrypted.
        :return: Encrypted `num`.
        """

        if num >= self._mod:
            raise OverflowError("Integer {} is too big for encryption".format(num))

        return pow(num, self._exp, self._mod)

    def decrypt_int(self,
                    num: int) -> int:
        """Decrypt integer `num`.

        RSA can only decrypt a number smaller than the key (num < key.mod).

        :param num: The number to be decrypted.
        :return: Decrypted `num`.
        """

        if num >= self._mod:
            raise OverflowError("Integer {} is too big for decryption".format(num))

        return pow(num, self._exp, self._mod)

    def encrypt(self,
                message: PlainText) -> Cipher:
        """Encrypt `message`.

        :param message: The message to be encrypted - must be a bytes-like object.
        :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
        :return: Encrypted `message`.
        """

        e, n = k.exp, k.mod

        p = message.to_int(self.byte_size())

        c = pow(message, e, n)

        cipher = c.to_bytes(key_len, 'big')

        return cipher

    def decrypt(cipher, k):
        """Decrypt `cipher` with key `k`.

        The message bytes sequence is treated as big endian integer.

        :param cipher: The message to be decrypted - must be a bytes-like object.
        :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
        :return: Encrypted `message`.
        """

        d, n = k.exp, k.mod

        cipher = int.from_bytes(cipher, 'big')

        p = pow(cipher, d, n)

        message = p.to_bytes(key_len, "big")
        message = unpad_bytes(message)

        return message

class RsaPublicKey(RsaKey):
    """RSA public key."""


class RsaPrivateKey(RsaKey):
    """RSA private key."""
