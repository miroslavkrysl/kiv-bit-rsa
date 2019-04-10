"""Useful mathematical functions for the RSA cipher.
"""

from random import getrandbits
from random import randrange


def is_prime(num, rounds=40):
    """Test if `num` is prime number.

    Uses the Miller-Rabin probabilistic primality test.
    The certainty of error is (1/4)^`rounds`.

    :param num: The number to be tested for primality.
    :param rounds: Number of testing rounds.
    :return: True if `num` is prime, False otherwise
    """

    num = int(num)

    if num == 1 or num == 2:
        return True

    if num % 2 == 0:
        return False

    r = 0
    s = num - 1

    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(rounds):
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


def random_prime(n_bits):
    """Generate a prime number with length of `n_bits`.

    :param n_bits: Number of bits ot the prime.
    :return: Random prime.
    """

    while True:

        num = getrandbits(n_bits)

        # make sure the number is odd
        num |= 1

        # make sure the number has exactly n_bits
        num |= 2 ** (n_bits - 1)

        if is_prime(num):
            return num


def mod_inverse(a, n):
    """
    Compute the modular multiplicative inverse of `a` modulo `n`.

    :param a: The integer to be inverted.
    :param n: The modulo n.
    :return: The modular multiplicative inverse of `a` if exists, None otherwise.
    """

    if n == 0:
        return None

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
