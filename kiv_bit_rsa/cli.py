"""CLI interface module for kiv_bit_rsa.

Consists of key generation, encryption/decryption and file
signing and verifying
"""

import click

from kiv_bit_rsa.hash import Md5
from kiv_bit_rsa.rsa import Rsa, TomlKeyFormatter, KeyFormatError
from kiv_bit_rsa.rsa.rsa import DecryptError
from kiv_bit_rsa.sign import SignableBinaryIO, Signature
from kiv_bit_rsa.sign.signature_formatter import TomlSignatureFormatter, SignatureFormatError


@click.group()
def cli():
    """RSA cipher utilities for encryption/decryption and signing/verifying files."""
    pass


@click.command()
@click.option('-b', '--bits', default=2048, type=click.IntRange(16, 8192), help='number of bits for storing key modulus n')
@click.option('-d', '--private_key_file', 'private', default="rsa-key.private.toml", type=click.File('w'), help='filepath where to store private key')
@click.option('-e', '--public_key_file', 'public', default="rsa-key.public.toml", type=click.File('w'), help='filepath where to store public key')
def keygen(bits, private, public):
    """Generate pair of RSA keys."""

    rsa = Rsa()
    keys = rsa.generate_keys(bits)

    formatter = TomlKeyFormatter()

    private.write(formatter.to_string(keys.private_key))
    public.write(formatter.to_string(keys.public_key))


@click.command()
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the encryption key')
@click.option('-p', '--plaintext', 'plaintext', type=click.File('rb'), help='filepath where to read plaintext from')
@click.option('-c', '--cipher', 'cipher', type=click.File('wb'), help='filepath where to print the cipher into')
def encrypt(key, plaintext, cipher):
    """Encrypt a message using the RSA key."""

    rsa = Rsa()

    try:
        k = TomlKeyFormatter().from_string(key.read())

        p = plaintext.read()
        c = rsa.encrypt(p, k)

        cipher.write(c)

    except KeyFormatError:
        click.echo("ERROR: Key is in bad format")

    except OverflowError:
        click.echo("ERROR: Message is to long for encryption with the given key.")


@click.command()
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the decryption key')
@click.option('-c', '--cipher', 'cipher', type=click.File('rb'), help='filepath where to read cipher from')
@click.option('-p', '--plaintext', 'plaintext', type=click.File('wb'), help='filepath where to print plaintext into')
def decrypt(key, cipher, plaintext):
    """Decrypt a message using the RSA key."""

    rsa = Rsa()

    try:
        k = TomlKeyFormatter().from_string(key.read())

        c = cipher.read()
        p = rsa.decrypt(c, k)

        plaintext.write(p)

    except KeyFormatError:
        click.echo("ERROR: Key is in bad format")

    except DecryptError:
        click.echo("ERROR: Key is wrong or message was badly padded before encryption")


@click.command()
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the signing key')
@click.option('-f', '--file', 'file', required=True, type=click.File('rb'), help='filepath of the file that will be signed')
@click.option('-s', '--signature_file', 'sign', default="signature.toml", type=click.File('w'), help='filepath where to store the signature')
def sign(key, file, sign):
    """Sign a file using the MD5 hash and RSA key."""

    try:
        key = TomlKeyFormatter().from_string(key.read())
        signature = Signature.sign(SignableBinaryIO(file), Md5, key)

        sign.write(TomlSignatureFormatter().to_string(signature))

    except KeyFormatError:
        click.echo("ERROR: Key is in bad format")


@click.command()
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the decryption key')
@click.option('-f', '--file', 'file', required=True, type=click.File('rb'), help='filepath of the file that will be verified')
@click.option('-s', '--signature_file', 'sign', default="signature.toml", type=click.File('r'), help='filepath of the signature')
def verify(key, file, sign):
    """Verify a signed file."""

    try:
        key = TomlKeyFormatter().from_string(key.read())
        signature = TomlSignatureFormatter().from_string(sign.read())

        if signature.verify(SignableBinaryIO(file), key):
            click.echo("---verified---")
            exit(0)
        else:
            click.echo("---denied---")
            exit(1)

    except KeyFormatError:
        click.echo("ERROR: Key is in bad format")

    except SignatureFormatError:
        click.echo("ERROR: Signature is in bad format")


cli.add_command(keygen)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(sign)
cli.add_command(verify)


if __name__ == '__main__':
    cli()
