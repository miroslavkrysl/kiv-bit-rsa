from math import gcd
from random import randint

from kiv_bit_rsa.math import get_random_prime, modular_multiplicative_inverse


def generate_keys(n_bits=2048):
    """
    Generate RSA private and public keys of size n_bits.
    :param n_bits: The size of the
    :return: A tuple consisting of the private key and the public key ((d, n), (e, n))
    """

    p = get_random_prime(n_bits // 2)
    q = get_random_prime(n_bits // 2)

    n = p * q
    x = (p - 1) * (q - 1)

    # get random number for public key
    e = 0
    while True:
        e = randint(2, x - 1)

        if gcd(e, x) == 1:
            break

    # get multiplicative inverse for private key
    d = modular_multiplicative_inverse(e, n)

    return (d, n), (e, n)

# TODO: implement encrypt, decrypt in rsa
