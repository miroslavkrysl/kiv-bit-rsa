"""Math module
A simple math module containing a couple of mathematical functions
used by the RSA cipher.
"""

from kiv_bit_rsa.math.math import get_random_prime, is_prime, modular_multiplicative_inverse

__all__ = ["get_random_prime", "is_prime", "modular_multiplicative_inverse"]
