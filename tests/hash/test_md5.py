from kiv_bit_rsa.hash import Md5


def test_hash_len():
    hash1 = Md5(b"Hello world!")
    hash2 = Md5(b"Hello world! Hello world! Hello world! Hello world! Hello world! Hello world!")
    assert len(hash1.to_hex()) == 32
    assert len(hash2.to_hex()) == 32


def test_validity():
    hash1 = Md5(b"Hello world!")
    assert hash1.to_hex() == "86fb269d190d2c85f6e0468ceca42a20"


def test_validity_diacritics():
    hash1 = Md5("ěščřřžýááí".encode("utf8"))
    assert hash1.to_hex() == "f41562989870cb1427341bc4b8c1af35"


def test_digest_equals():
    hash1 = Md5(b"Hello world!")
    hash2 = Md5(b"Hello world!")
    assert hash1.to_bytes() == hash2.to_bytes()


def test_digest_not_equals():
    hash1 = Md5(b"hello world!")
    hash2 = Md5(b"Hello world!")
    assert hash1.to_bytes() != hash2.to_bytes()


def test_hex_digest_equals():
    hash1 = Md5(b"Hello world!")
    hash2 = Md5(b"Hello world!")
    assert hash1.to_hex() == hash2.to_hex()


def test_hex_digest_not_equals():
    hash1 = Md5(b"hello world!")
    hash2 = Md5(b"Hello world!")
    assert hash1.to_hex() != hash2.to_hex()


def test_hash_update():
    hash1 = Md5(b"Hello world!")
    hash2 = Md5(b"Hello")
    hash2.update(b" world!")
    assert hash1.to_bytes() == hash2.to_bytes()
    assert hash1.to_hex() == hash2.to_hex()
