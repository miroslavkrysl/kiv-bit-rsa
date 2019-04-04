from struct import iter_unpack, pack


class Md5:
    """The class representing an md5 hash object.
    """

    _a_init = 0x67452301
    _b_init = 0xefcdab89
    _c_init = 0x98badcfe
    _d_init = 0x10325476

    _s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
          5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    _k = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
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

    def __init__(self, data=None):
        """Initialize an MD5 hash object with optional initial data.

        :param data: The initial data, must by bytes-like object.
        """

        self._buffer = bytearray()
        self._size = 0
        self._state = [self._a_init,
                       self._b_init,
                       self._c_init,
                       self._d_init]

        if data:
            self.update(data)

    @staticmethod
    def _f(b, c, d):
        return (b & c) | ((b ^ 0xffffffff) & d)

    @staticmethod
    def _g(b, c, d):
        return (b & d) | (c & (d ^ 0xffffffff))

    @staticmethod
    def _h(b, c, d):
        return b ^ c ^ d

    @staticmethod
    def _i(b, c, d):
        return c ^ (b | (d ^ 0xffffffff))

    @staticmethod
    def _rotate_left(num, bits):
        """
        Rotate the `num` `bits` bits left using the 32bit unsigned rotation.

        :param num: The number to be rotated.
        :param bits: The number of bits.
        :return: Rotated number.
        """

        return ((num << bits) | (num >> (32 - bits))) & 0xffffffff

    @classmethod
    def _hash_block(cls, block):
        """
        Hash the block and add the hash into `_state`

        :param block: The 64 bytes long block to be hashed.
        """

        a, b, c, d = cls._a_init, cls._b_init, cls._c_init, cls._d_init

        # extract 32 bit uints from block
        block = [i[0] for i in iter_unpack("<I", block)]

        print(block)

        for i in range(64):
            f = 0
            k = cls._k[i]
            m = 0
            s = cls._s[i]

            if i < 16:
                f = cls._f(b, c, d)
                m = block[i]
            elif i < 32:
                f = cls._g(b, c, d)
                m = block[(5 * i + 1) % 16]
            elif i < 48:
                f = cls._h(b, c, d)
                m = block[(3 * i + 5) % 16]
            else:
                f = cls._i(b, c, d)
                m = block[(7 * i) % 16]

            f = (f + a + k + m) & 0xffffffff
            a = d
            d = c
            c = b
            b = (b + cls._rotate_left(f, s)) & 0xffffffff

            print(i, a, b, c, d)

        return a, b, c, d

    def _finalize(self):
        """
        Get finalized hash.

        :return: The hash tuple of ints - (A, B, C, D)
        """

        # pad the data with byte 0b10000000
        block = self._buffer + b'\x80'

        # pad with zeros
        while len(block) % 64 != 56:
            block += b'\x00'

        # add data size at the end
        block += pack("<Q", self._size * 8)

        hashed = self._hash_block(block)

        return [(s + h) & 0xffffffff for s, h in zip(self._state, hashed)]

    def update(self, data):
        """
        Update the hash with given bytes.

        :param data: The bytes-like object.
        """

        # TODO: optimize

        for byte in data:
            self._buffer.append(byte)
            self._size += 1 % 64

            if len(self._buffer) == 64:
                hashed = self._hash_block(self._buffer)

                self._state = [(s + h) & 0xffffffff for s, h in zip(self._state, hashed)]

                self._buffer.clear()

    def digest(self):
        """
        Get the digest in bytes.
        :return: The digest bytes.
        """
        return b''.join([pack("<I", i) for i in self._finalize()])

    def hex_digest(self):
        """
        Get the digest in hexadecimal representation.
        :return: The hex string.
        """
        return ''.join([format(i, '>02x') for i in self.digest()])
