"""
Useful mathematical functions for the RSA cipher.
"""

from math import ceil
from math import log
from random import getrandbits
from random import randrange


def is_prime(num, certainty=0.99):
    """
    Test if num is prime number using the Miller-Rabin primarily test.
    The certainty, that num is prime will be higher then given certainty.

    :param num: The integer number to be tested.
    :param certainty: The minimal certainty - must between 0.0 and 1.0 exclusively.
    :return: True if the num is prime, False otherwise.
    """

    if certainty <= 0.0 or certainty >= 1.0:
        raise ValueError('certainty is out of range')

    num = int(num)

    if num <= 1:
        return False

    if num == 2:
        return True

    if num % 2 == 0:
        return False

    # compute minimum of required iterations to reach to desired certainty
    k = - int(ceil(log(4, certainty)))

    r = 0
    s = num - 1

    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = randrange(2, num - 1)
        x = pow(a, s, num)

        if x == 1 or x == num - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False

    return True


def get_random_prime(n_bits, prime_certainty=0.99):
    """
    Generate a prime number with maximal length of n_bits.

    :param n_bits: The maximum number of number bits.
    :param prime_certainty: The certainty of the number to by the prime
    :return: The integer prime number.
    """

    while True:
        num = getrandbits(n_bits)

        if is_prime(num, prime_certainty):
            return num


def modular_multiplicative_inverse(a, n):
    """
    Compute the modular multiplicative inverse of a modulo n.

    :param a: The integer to be inverted.
    :param n: The modulo n.
    :return: The modular multiplicative inverse of a if exists, None otherwise.
    """

    t = 0
    new_t = 1

    r = n
    new_r = a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        return None

    if t < 0:
        t = t + n

    return t
