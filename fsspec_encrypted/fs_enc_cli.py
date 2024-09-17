import argparse
import fsspec
from cryptography.fernet import Fernet
import sys
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from fsspec_encrypted.fs_enc import EncryptedFS


def generate_key(passphrase=None, salt=None):
    """Generates a new encryption key, optionally from a passphrase, and prints it to stdout."""
    if passphrase:
        verbose = False
        if not salt:
            verbose = True
        key, salt = generate_key_from_passphrase(passphrase, salt)
        
        if verbose:
            print(f"Derived Key: {EncryptedFS.key_to_str(key)}")
            print(f"Salt (in hex): {salt.hex()}")
        else:
            return key
            
    else:
        key = Fernet.generate_key()
        return key

def generate_key_from_passphrase(passphrase: str, salt: bytes = None) -> bytes:
    """Derive a Fernet key from a passphrase using PBKDF2HMAC."""
    if salt is None:
        # It's important to use a unique, random salt for each key derivation
        salt = os.urandom(16)

    key = EncryptedFS.derive_key(passphrase, salt)
    
    return key, salt

def encrypt_and_write(encryption_key, filename, input_data):
    """Encrypts input data and writes it to the specified file."""
    enc_fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    enc_fs.writetext(filename, input_data)
    print(f"Data has been encrypted and written to {filename}")


def decrypt_and_read(encryption_key : bytes, filename):
    """Decrypts data from the specified file and prints it."""
    enc_fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    decrypted_data = enc_fs.readtext(filename)
    #print(f"{decrypted_data}")
    return decrypted_data

# pragma: no cover
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using fsspec-encrypted.")
    subparsers = parser.add_subparsers(dest="command")

    # Generate key command with optional passphrase and salt
    parser_gen_key = subparsers.add_parser("gen-key", help="Generate a new encryption key.")
    parser_gen_key.add_argument("--passphrase", help="Passphrase to derive the encryption key.")
    parser_gen_key.add_argument("--salt", help="Optional salt (hex-encoded) to use with the passphrase.")

    # Encrypt command
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt input and write to a file.")
    parser_encrypt.add_argument("--key", required=True, help="Encryption key for encrypting files. Should be a base64-encoded string.")
    parser_encrypt.add_argument("--file", required=True, help="File path to write encrypted data.")

    # Decrypt command
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a file and print the result.")
    parser_decrypt.add_argument("--key", required=True, help="Encryption key for decrypting files. Should be a base64-encoded string.")
    parser_decrypt.add_argument("--file", required=True, help="File path to read and decrypt.")

    args = parser.parse_args()

    if args.command == "gen-key":
        salt = bytes.fromhex(args.salt) if args.salt else None
        key = generate_key(args.passphrase, salt)
        if key is not None:
            print(EncryptedFS.key_to_str(key))
            
    elif args.command == "encrypt":
        # Read input data from stdin
        input_data = sys.stdin.read()
        key = EncryptedFS.str_to_key(args.key)
        encrypt_and_write(key, args.file, input_data)
    elif args.command == "decrypt":
        key = EncryptedFS.str_to_key(args.key)
        print(decrypt_and_read(key, args.file))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
