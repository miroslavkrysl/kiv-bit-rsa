"""Hashing module
A simple module for hashing.

Contains base class :py:class:`Hash` from which all
hash implementations inherits.
For now contains only MD5 hash class :py:class:`Md5`
"""

from kiv_bit_rsa.hash.hash import Hash
from kiv_bit_rsa.hash.md5 import Md5

__all__ = ["Md5"]
