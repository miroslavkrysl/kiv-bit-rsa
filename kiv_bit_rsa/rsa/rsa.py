"""RSA cipher key generation and encryption/decryption.
"""

from math import gcd, ceil
from random import randint

from kiv_bit_rsa.math import random_prime, mod_inverse
from kiv_bit_rsa.package import KivBitRsaError
from kiv_bit_rsa.rsa.key import PrivateKey, PublicKey


class WrongPaddingError(KivBitRsaError):
    """Message is badly padded"""


def byte_len(num):
    """Get number of required bytes for integer `num`.

    :param num: The number to check for required bytes.
    :return: The number of bytes required by `num`.
    """

    if num == 0:
        return 1

    return ceil(num.bit_length() / 8)


def pad_bytes(message, length):
    """Pad message with into desired `length`.

    :param message: The message to pad.
    :param length: The message length wanted after pad.
    :return: Padded message.
    """

    if len(message) + 3 > length:
        raise OverflowError('Message is too long for padding')

    n_pad_bytes = length - len(message) - 2

    message = b''.join([
        b'\x00',
        b'\xFF' * n_pad_bytes,
        b'\x00',
        message
    ])

    return message


def unpad_bytes(message):
    """Remove padding from the message.

    :param message: The message to unpad.
    :return: Unpadded message.
    """

    if message[0:2] != b'\x00\xFF':
        raise WrongPaddingError("Padded message doesn't start with bytes 0x00 0xFF")

    try:
        message_start = message.index(b'\x00', 2) + 1
    except ValueError:
        raise WrongPaddingError("Message starts with bytes 0x00 0xFF, but doesn't contain message start byte 0x00")

    return message[message_start:]


def generate_keys(n_bits=2048):
    """Generate RSA private and public keys of size n_bits.

    :param n_bits: Number of key modulus bits.
    :return: Dict consisting of {'private': PrivateKey, 'public': PublicKey}.
    """

    if n_bits < 16:
        raise ValueError('Key is too small')

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

    return {'private': PrivateKey(d, n), 'public': PublicKey(e, n)}


def encrypt_int(num, k):
    """Encrypt `num` with key `k`.

    RSA can only encrypt a number smaller than the key (modulus `n`).

    :param num: The number to be encrypted.
    :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
    :return: Encrypted `num`.
    """

    e, n = k.exp, k.mod

    if num >= n:
        raise OverflowError("Message is too big for encryption")

    return pow(num, e, n)


def decrypt_int(num, k):
    """Decrypt `num` with key `k`.

    RSA can only decrypt a number smaller than the key (modulus `n`).

    :param num: The number to be decrypted.
    :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
    :return: Decrypted `num`.
    """

    d, n = k.exp, k.mod

    if num >= n:
        raise OverflowError("Message is too big for decryption")

    return pow(num, d, n)


def encrypt(message, k):
    """Encrypt `message` with key `k`.

    The message bytes sequence is treated as big endian integer.

    :param message: The message to be encrypted - must be a bytes-like object.
    :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
    :return: Encrypted `message`.
    """

    e, n = k.exp, k.mod
    key_len = byte_len(n)

    message = pad_bytes(message, key_len)
    message = int.from_bytes(message, 'big')

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
    key_len = byte_len(n)

    cipher = int.from_bytes(cipher, 'big')

    p = pow(cipher, d, n)

    message = p.to_bytes(key_len, "big")
    message = unpad_bytes(message)

    return message
