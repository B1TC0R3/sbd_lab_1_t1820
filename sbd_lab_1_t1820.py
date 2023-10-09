# Copyright © 2023 Thomas Gingele https://github.com/B1TC0R3
import argparse
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash      import SHA256
from Crypto.Signature import pkcs1_15


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Solver for SBD Laboratory Task 18/20',
        epilog='Copyright © 2023 Thomas Gingele https://github.com/B1TC0R3'
    )

    parser.add_argument(
        '-priv',
        '--private-key',
        help='a RSA private key file',
        required=True
    )
    
    parser.add_argument(
        '-pub',
        '--public-key',
        help='a RSA public key file',
        required=True
    )

    return parser.parse_args()


def openssl_format(value: int) -> str:
    return hex(value)[2:].upper()


def main():
    args        = get_args()
    private_key = None
    public_key  = None

    with open(args.private_key) as key_file:
        private_key = RSA.import_key(key_file.read())

    with open(args.public_key) as key_file:
        public_key = RSA.import_key(key_file.read())

    signer   = pkcs1_15.new(private_key)
    verifier = pkcs1_15.new(public_key)

    # Remove prepending '0x' from hex string and uppercase it to match OpenSSL output
    modulus          = openssl_format(private_key.n)
    public_exponent  = openssl_format(private_key.d)
    private_exponent = openssl_format(private_key.e)

    data      = SHA256.new(modulus.encode())
    signature = signer.sign(data)
    b64_sign  = base64.b64encode(signature).decode()

    # This will raise a 'ValueError' if the signature is invalid
    verifier.verify(data, signature)

    print(f"MODULUS: {modulus}\n")
    print(f"PUBLIC EXPONENT: {public_exponent}\n")
    print(f"PRIVATE EXPONENT: {private_exponent}\n")
    print(f"SIGNATURE: {b64_sign}\n")


if __name__ == '__main__':
    main()
