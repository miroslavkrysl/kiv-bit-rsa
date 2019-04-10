"""MD5 module
A simple module for hashing.

Contains base class :py:class:`kiv_bit_rsa.hashing.HashingMethod` from which all
hashing implementations inherits.
For now contains only MD5 hashing class :py:class:`kiv_bit_rsa.hashing.Md5`
"""

from kiv_bit_rsa.hashing.base import HashingMethod
from kiv_bit_rsa.hashing.md5 import Md5

__all__ = ["Md5"]
