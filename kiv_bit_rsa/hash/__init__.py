"""Hashing module
A simple module for hashing.

Contains base class :py:class:`Hash` from which all
hash implementations inherits.
For now contains only MD5 hash class :py:class:`Md5`
"""

from .hash import Hash
from .md5 import Md5

__all__ = ["Hash", "Md5"]
