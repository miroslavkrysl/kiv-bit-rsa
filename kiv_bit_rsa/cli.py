"""CLI interface module for RSA.

Consists of key generation, encryption/decryption and file
signing and verifying
"""

import click


@click.group()
def cli():
    pass


@click.command(help="Generate pair of RSA keys.")
@click.option('-b', '--bits', default=2048, type=click.IntRange(16, 8192), help='number of bits for storing key modulus n')
@click.option('-d', '--private_key_file', 'private', default="rsa-key.public.toml", type=click.File('w'), help='filepath where to store private key')
@click.option('-e', '--public_key_file', 'public', default=1, help='filepath where to store public key')
def keygen(bits, private, public):
    click.echo('Generating')


@click.command(help="Encrypt a message using the RSA key.")
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the encryption key')
@click.option('-f', '--input', 'inp', default="-", type=click.File('r'), help='filepath where to read message from')
@click.option('-o', '--output', 'out', default="-", type=click.File('w'), help='filepath where to print encrypted message into')
def encrypt(key, input, output):
    click.echo('Encrypting')


@click.command(help="Decrypt a message using the RSA key.")
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the decryption key')
@click.option('-f', '--input', 'inp', default="-", type=click.File('r'), help='filepath where to read encrypted message from')
@click.option('-o', '--output', 'out', default="-", type=click.File('w'), help='filepath where to print decrypted message into')
def decrypt(key, inp, out):
    click.echo('Decrypting')


@click.command(help="Sign a file using the MD5 hash and RSA key.")
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the signing key')
@click.option('-f', '--file', 'file', required=True, type=click.File('r'), help='filepath of the file that will be signed')
@click.option('-s', '--signature_file', 'sign', default="signature.toml", type=click.File('w'), help='filepath where to store the signature')
def sign(key, file, sign):
    click.echo('Signing')


@click.command(help="Verify a signed file.")
@click.option('-k', '--key_file', 'key', required=True, type=click.File("r"), help='filepath of the decryption key')
@click.option('-f', '--file', 'file', required=True, type=click.File('r'), help='filepath of the file that will be verified')
@click.option('-s', '--signature_file', 'sign', default="signature.toml", type=click.File('r'), help='filepath of the signature')
def verify(key, file, sign):
    click.echo('Verifying')


cli.add_command(keygen)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(sign)
cli.add_command(verify)


if __name__ == '__main__':
    cli()