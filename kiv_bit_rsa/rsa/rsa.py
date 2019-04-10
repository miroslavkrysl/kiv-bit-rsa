"""RSA cipher key generation and encryption/decryption.
"""

from math import gcd
from random import randint

from kiv_bit_rsa.math import random_prime, mod_inverse
from kiv_bit_rsa.rsa.key import PrivateKey, PublicKey


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


def encrypt(message, k):
    """Encrypt `message` with key `k`.

    RSA can only encrypt message which's integer value is smaller
    than the key (modulus `n`).


    The message bytes sequence is treated as big endian integer.

    :param message: The message to be encrypted - must be a bytes-like object.
    :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
    :return: Encrypted `message`.
    """

    e, n = k.exp, k.mod

    message = int.from_bytes(message, 'big')

    if message >= n:
        raise OverflowError("Message is too big for decryption")

    return pow(message, e, n)


def decrypt(message, k):
    """Decrypt `message` with key `k`.

    RSA can only decrypt message which's integer value is smaller
    than the key (modulus `n`).

    The message bytes sequence is treated as big endian integer.

    :param message: The message to be decrypted - must be a bytes-like object.
    :param k: The key - instance of :py:class:`kiv_bit_rsa.rsa.Key`.
    :return: Encrypted `message`.
    """

    d, n = k.exp, k.mod

    message = int.from_bytes(message, 'big')

    if message >= n:
        raise OverflowError("Message is too big for decryption")

    return pow(message, d, n)
