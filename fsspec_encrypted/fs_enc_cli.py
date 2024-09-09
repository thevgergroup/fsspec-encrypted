import argparse
import fsspec
from cryptography.fernet import Fernet
import sys

def generate_key():
    """Generates a new encryption key and prints it to stdout."""
    key = Fernet.generate_key()
    print(f"{key.decode()}")

def determine_filesystem(file_path :str):
    """
    Determines the filesystem type based on the file path.
    Returns the fsspec filesystem and the cleaned path.
    """
    if file_path.startswith("s3://"):
        #fs = fsspec.filesystem('s3')
        return "s3", file_path
    elif file_path.startswith("gcs://"):
        fs = fsspec.filesystem('gcs')
    elif file_path.startswith("ftp://"):
        fs = fsspec.filesystem('ftp')
    else:
        # Default to local filesystem
        fs = fsspec.filesystem('file')

    return fs, file_path

def encrypt_and_write(encryption_key, filename, input_data):
    """Encrypts input data and writes it to the specified file."""
    fs, path = determine_filesystem(filename)
    print(fs)
    enc_fs = fsspec.filesystem('enc', root_path=path, encryption_key=encryption_key, underlying_fs=fs)
    enc_fs.writetext(filename, input_data)
    print(f"Data has been encrypted and written to {filename}")

def decrypt_and_read(encryption_key, filename):
    """Decrypts data from the specified file and prints it."""
    fs, path = determine_filesystem(filename)
    enc_fs = fsspec.filesystem('enc', root_path=path, encryption_key=encryption_key, underlying_fs=fs)
    decrypted_data = enc_fs.readtext(filename)
    print(f"Decrypted data from {filename}:\n{decrypted_data}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using fsspec-encrypted.")
    subparsers = parser.add_subparsers(dest="command")

    # Generate key command
    parser_gen_key = subparsers.add_parser("gen-key", help="Generate a new encryption key.")

    # Encrypt command
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt input and write to a file.")
    parser_encrypt.add_argument("--key", required=True, help="Encryption key for encrypting files.")
    parser_encrypt.add_argument("--file", required=True, help="File path to write encrypted data.")

    # Decrypt command
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a file and print the result.")
    parser_decrypt.add_argument("--key", required=True, help="Encryption key for decrypting files.")
    parser_decrypt.add_argument("--file", required=True, help="File path to read and decrypt.")

    args = parser.parse_args()

    if args.command == "gen-key":
        generate_key()
    elif args.command == "encrypt":
        # Read input data from stdin
        input_data = sys.stdin.read()
        encrypt_and_write(args.key, args.file, input_data)
    elif args.command == "decrypt":
        decrypt_and_read(args.key, args.file)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
