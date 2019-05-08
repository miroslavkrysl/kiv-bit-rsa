"""RSA cipher key generation and encryption/decryption.
"""

from math import gcd, ceil
from random import randint

from kiv_bit_rsa.math import random_prime, mod_inverse
from kiv_bit_rsa.exception import KivBitRsaError
from kiv_bit_rsa.rsa.key import PrivateKey, PublicKey, KeyPair, Key


class RsaError(KivBitRsaError):
    """Base class for RSA cipher errors"""


class WrongPaddingError(RsaError):
    """Message is badly padded."""


class KeyTooShortError(RsaError):
    """Key length is too small."""


class DecryptError(RsaError):
    """Decryption failed."""


class Rsa:
    """RSA cipher."""

    KEY_LEN_MIN = 16
    """Minimum length of the key modulus"""

    PAD_BYTE_START = b'\x00'
    """First byte of padding"""

    PAD_BYTE_FILL = b'\xFF'
    """Middle (fill) byte of padding"""

    PAD_BYTE_END = b'\x00'
    """Last byte of padding"""

    BYTE_ORDER = 'big'
    """Message bytes to int byte order."""

    def generate_keys(self, n_bits: int = 2048) -> KeyPair:
        """Generate RSA private and public keys of size n_bits.

        :param n_bits: Number of key modulus bits.
        :raise KeyTooShortError: When given key size is too small.
        :return: The key pair.
        """

        if n_bits < self.KEY_LEN_MIN:
            raise KeyTooShortError('Key is too small. Minimum is {}'.format(self.KEY_LEN_MIN))

        p = random_prime(n_bits // 2)
        q = random_prime(n_bits // 2)

        n = p * q
        x = (p - 1) * (q - 1)

        # get random number for public key
        while True:
            e = randint(1, x - 1)

            if gcd(e, x) == 1:
                break

        # get multiplicative inverse for private key
        d = mod_inverse(e, x)

        return KeyPair(PrivateKey(d, n), PublicKey(e, n))

    def encrypt(self,
                message: bytes,
                key: Key) -> bytes:
        """Encrypt `message` with key `key`.

        :param message: The message to encrypt.
        :param key: The encryption key.
        :raise OverflowError: When message is too long for encryption padding.
        :return: Encrypted `message`.
        """

        p = int.from_bytes(self._pad_message(message, key.byte_size()), self.BYTE_ORDER)

        c = key.encrypt(p)

        return c.to_bytes(key.byte_size(), self.BYTE_ORDER)

    def decrypt(self,
                cipher: bytes,
                key: Key) -> bytes:
        """Decrypt `cipher` with key `key`.

        The message bytes sequence is treated as big endian integer.

        :param cipher: The cipher to decrypt.
        :param key: The decryption key.
        :raise DecryptError: When message is wrongly decrypted - caused by wrong key or bad padding.
        :return: Decrypted `cipher`.
        """

        c = int.from_bytes(cipher, self.BYTE_ORDER)

        p = key.decrypt(c)

        try:
            unpadded = self._unpad_message(p.to_bytes(key.byte_size(), self.BYTE_ORDER))

        except WrongPaddingError:
            raise DecryptError("Message can not be decrypted.")

        return unpadded

    def _pad_message(self,
                     message: bytes,
                     length: int) -> bytes:
        """Pad message into desired `length`.

        :param message: The message to pad.
        :param length: The message length wanted after pad.
        :raise OverflowError: When message is too long for padding.
        :return: Padded message.
        """

        if len(message) + 3 > length:
            raise OverflowError('Message is too long for padding to {} bytes'.format(length))

        n_pad_bytes = length - len(message) - 2

        padded = b''.join([
            self.PAD_BYTE_START,
            self.PAD_BYTE_FILL * n_pad_bytes,
            self.PAD_BYTE_END,
            message
        ])

        return padded

    def _unpad_message(self,
                       message: bytes) -> bytes:
        """Remove padding from the message.

        :param message: The message to unpad.
        :raise WrongPaddingError: When message is badly padded.
        :return: Unpadded message.
        """

        if message[0:2] != self.PAD_BYTE_START + self.PAD_BYTE_FILL:
            raise WrongPaddingError(
                "Padded message doesn't start with bytes {} {}".format(self.PAD_BYTE_START, self.PAD_BYTE_FILL))

        try:
            message_start = message.index(self.PAD_BYTE_END, 2) + 1
        except ValueError:
            raise WrongPaddingError(
                "Message starts with bytes {} {}, but doesn't contain message start byte {}".format(
                    self.PAD_BYTE_START,
                    self.PAD_BYTE_FILL,
                    self.PAD_BYTE_END
                ))

        return message[message_start:]
