"""Math module

A simple math module containing a couple of mathematical functions
used by the RSA cipher.
"""

from .math import random_prime, is_prime, mod_inverse

__all__ = ["random_prime", "is_prime", "mod_inverse"]
