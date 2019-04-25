"""MD5 hash implementation.
"""

from struct import iter_unpack, pack
from typing import Tuple, List, cast

from .hash import Hash


class Md5(Hash):
    """Md5 hash representation.

    The Md5 hash has four parts - a, b, c, d. Every part
    is a 32 bit unsigned integer and has the initial
    value:
    * a = 0x67452301
    * b = 0xefcdab89
    * c = 0x98badcfe
    * d = 0x10325476

    Every data chuck's hash is added to the values
    a, b, c, d.
    """

    _block_size = 64

    _a_init = 0x67452301
    _b_init = 0xefcdab89
    _c_init = 0x98badcfe
    _d_init = 0x10325476

    _s: List[int] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                     5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                     4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                     6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    _k: List[int] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                     0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                     0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                     0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                     0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                     0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                     0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                     0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                     0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

    def __init__(self,
                 data: bytes = None):
        """Initialize an MD5 hasher with optional initial data.

        :param data: The initial data.
        """

        self._buffer = bytearray()
        self._size = 0

        self._state = (
            self._a_init,
            self._b_init,
            self._c_init,
            self._d_init
        )

        if data:
            self.update(data)

    @classmethod
    def chunk_size(cls) -> int:
        """Get size of the Md5 data chunk.

        Get the size of the chunk of bytes that is processed
        during one round of the method. Size of Md5 data chunk
        is 64 bytes.

        :return: Size of the chunk in bytes = 64 B.
        """

        return cls._block_size

    def update(self,
               data: bytes):
        """Update the hash with `data`.

        :param data: The data to update the hash with.
        """

        # TODO: optimize

        for byte in data:
            self._buffer.append(byte)
            self._size += 1 % 64

            if len(self._buffer) == 64:
                hashed = self._hash_chunk(self._buffer)

                self._state = [(s + h) & 0xffffffff for s, h in zip(self._state, hashed)]

                self._buffer.clear()

    def to_bytes(self) -> bytes:
        """Get the hash digest as bytes.

        :return: The digest as bytes.
        """

        return b''.join([pack("<I", i) for i in self._finalize()])

    def to_hex(self) -> str:
        """Get the hash digest as a hex string.

        :return: The digest as a hex string.
        """
        return ''.join([format(i, '>02x') for i in self.to_bytes()])

    @staticmethod
    def _f(b: int,
           c: int,
           d: int) -> int:
        """Function F used in hash: (b & c) | (~b & d).

        Computes in 32 bit arithmetic.

        :param b: The hash part B.
        :param c: The hash part C.
        :param d: The hash part D.
        :return: Result of function F.
        """

        return (b & c) | ((b ^ 0xffffffff) & d)

    @staticmethod
    def _g(b: int,
           c: int,
           d: int) -> int:
        """Function G used in hash: (b & d) | (c & ~d).

        Computes in 32 bit arithmetic.

        :param b: The hash part B.
        :param c: The hash part C.
        :param d: The hash part D.
        :return: Result of function G.
        """

        return (b & d) | (c & (d ^ 0xffffffff))

    @staticmethod
    def _h(b: int,
           c: int,
           d: int) -> int:
        """Function H used in hash = b ^ c ^ d.

        Computes in 32 bit arithmetic.

        :param b: The hash part B.
        :param c: The hash part C.
        :param d: The hash part D.
        :return: Result of function H.
        """

        return b ^ c ^ d

    @staticmethod
    def _i(b: int,
           c: int,
           d: int) -> int:
        """Function I used in hash = c ^ (b | ~d).

        Computes in 32 bit arithmetic.

        :param b: The hash part B.
        :param c: The hash part C.
        :param d: The hash part D.
        :return: Result of function I.
        """

        return c ^ (b | (d ^ 0xffffffff))

    @staticmethod
    def _rotate_left(num: int,
                     bits: int) -> int:
        """Rotate the `num` `bits` bits left using the 32bit unsigned rotation.

        Computes in 32 bit arithmetic.

        :param num: The number to be rotated.
        :param bits: The number of bits.
        :return: Rotated `num`.
        """

        return ((num << bits) | (num >> (32 - bits))) & 0xffffffff

    @classmethod
    def _hash_chunk(cls,
                    chunk: bytes) -> Tuple[int, int, int, int]:
        """Hash the data chunk.

        :param chunk: The 64 bytes long chunk to hash.
        :return: The chunk hash - tuple of ints (A, B, C, D)
        """

        a: int = cls._a_init
        b: int = cls._b_init
        c: int = cls._c_init
        d: int = cls._d_init

        # extract 32 bit uints from chunk
        chunk: List[int] = [i[0] for i in iter_unpack("<I", chunk)]

        for i in range(64):
            k = cls._k[i]
            s = cls._s[i]

            if i < 16:
                f = cls._f(b, c, d)
                m = chunk[i]
            elif i < 32:
                f = cls._g(b, c, d)
                m = chunk[(5 * i + 1) % 16]
            elif i < 48:
                f = cls._h(b, c, d)
                m = chunk[(3 * i + 5) % 16]
            else:
                f = cls._i(b, c, d)
                m = chunk[(7 * i) % 16]

            f = (f + a + k + m) & 0xffffffff
            a = d
            d = c
            c = b
            b = (b + cls._rotate_left(f, s)) & 0xffffffff

        return a, b, c, d

    def _finalize(self) -> Tuple[int, int, int, int]:
        """Get the finalized hash.

        :return: The final hash - tuple of ints (A, B, C, D)
        """

        # pad the data with byte 0b10000000
        block = self._buffer + b'\x80'

        # pad with zeros
        while len(block) % 64 != 56:
            block += b'\x00'

        # add data size at the end
        block += pack("<Q", self._size * 8)

        hashed = self._hash_chunk(block)

        result = tuple(((s + h) & 0xffffffff) for s, h in zip(self._state, hashed))

        return cast(Tuple[int, int, int, int], result)
