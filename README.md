# fsspec-encrypted

`fsspec-encrypted` is a Python package that provides an encrypted filesystem layer using the `fsspec` interface. It allows users to transparently encrypt and decrypt files while maintaining compatibility with any underlying `fsspec`-compatible filesystem (e.g., local, S3, GCS, etc.).

This is a port of [fs-encrypted](https://github.com/thevgergroup/fs-encrypted) to [fsspec](https://github.com/fsspec/filesystem_spec/) mainly because of inactivity and possible abandonment of the underlying file system pyfilesystem2.


- [fsspec-encrypted](#fsspec-encrypted)
  - [Note](#note)
  - [Key](#key)
  - [Features](#features)
  - [Application](#application)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Local Filesystem Example](#local-filesystem-example)
    - [S3 Filesystem Example](#s3-filesystem-example)
    - [Other Filesystems](#other-filesystems)
  - [CLI](#cli)
    - [Generate an Encryption Key](#generate-an-encryption-key)
    - [What is a Salt?](#what-is-a-salt)
    - [Encrypt data from stdin and write it to a file](#encrypt-data-from-stdin-and-write-it-to-a-file)
  - [Development](#development)
    - [Setting Up for Development](#setting-up-for-development)
    - [Running Tests](#running-tests)




## Note
`fsspec-encrypted` is an AES / Fernet encrypted driver for `fsspec`
A note about Fernet - it's great as an encryption method for smaller files, ideally those that fit in memory. 
As the entire file contents are used for decryption, ensuring if an attacker only gets a part of a file, then it's can't be used.

## Key
We use a Fernet key, ensure you store the keys securely!!!! A lost key means lost data! 

## Features

- **Encryption on top of any filesystem**: Works with any `fsspec`-supported filesystem (e.g., local, S3, GCS).
- **Automatic encryption and decryption**: Data is automatically encrypted during writes and decrypted during reads.
- **Pluggable with `fsspec`**: Easily integrate with `fsspec`'s existing ecosystem.
- **Simple and flexible**: Minimal setup required with flexible file system options.


## Application

Applications that may require sensitive data storage should use an encrypted file system. By providing a layer of abstraction on top of the encryption our hope is to make it easier to store this data.

PII / PHI
* Print Billing systems
* Insurance services / Identity cards
* Data Transfer
* Secure distributed configuration

Fernet is used as the encryption method (v0.1), this may become a configurable option in future revisions



## Installation

You can install `fsspec-encrypted` via pip from PyPI:

```bash
pip install fsspec-encrypted
```

## Usage

Here's a simple example of using `fsspec-encrypted` to create an encrypted filesystem layer on top of a local filesystem (default) and perform basic read and write operations.

### Local Filesystem Example

```python
import fsspec
from cryptography.fernet import Fernet

# Generate an encryption key
encryption_key = Fernet.generate_key()

# Create an EncryptedFS instance (local filesystem is the default)
enc_fs = fsspec.filesystem('enc', encryption_key=encryption_key)

# Write some encrypted data to a file
enc_fs.writetext('./encfs/example.txt', 'This is some encrypted text.')

# Read the encrypted data back from the file
print(enc_fs.readtext('./encfs/example.txt'))

```

### S3 Filesystem Example

```python
import fsspec
from cryptography.fernet import Fernet

# Generate an encryption key
encryption_key = Fernet.generate_key()

# Use the encrypted filesystem on top of an S3 filesystem
enc_fs = fsspec.filesystem('enc', encryption_key=encryption_key)

# Write some encrypted data to S3
enc_fs.writetext('s3://your-bucket/example.txt', 'This is some encrypted text.')

# Read the encrypted data back from S3
print(enc_fs.readtext('s3://your-bucket/example.txt'))
```

### Other Filesystems

`fsspec-encrypted` automatically determines the filesystem type based on the file path. 

For example, if the path starts with s3://, it will use S3; otherwise, it defaults to the local filesystem. It supports any fsspec-compatible filesystem (e.g., GCS, FTP).

## CLI

`fsspec-encrypted` also includes a command-line interface (CLI) for encrypting and decrypting files.

This allows a simple ability to encrypt and decrypt files without code
[![asciicast](https://asciinema.org/a/hwpcCH1r1CM7ezNU4fM6wgKiY.svg)](https://asciinema.org/a/hwpcCH1r1CM7ezNU4fM6wgKiY)

### Generate an Encryption Key
Store your keys appropriately - a secrets manager is an ideal solution! 

```bash
# Generate a random key
# CRITICAL STORE THE KEY SOMEWHERE SECURE
key=$(fs-enc gen-key)
```


If you want to generate a key based on a passphrase and salt 
```bash
fs-enc gen-key --passphrase 'hello world' --salt 12345432
```

### What is a Salt?
A salt is a random value used during the key derivation process to ensure that even if two people use the same passphrase, the derived encryption keys will be different. The salt is not a secret, but it should be unique and random for each encryption.

When encrypting data, the salt is usually stored alongside the encrypted data so that it can be used again during decryption to derive the same encryption key from the passphrase.


### Encrypt data from stdin and write it to a file

```bash
# Encrypt and store locally
echo "This is sensitive data" | fs-enc encrypt --key $key --file ./encfs/encrypted-file.txt
# Decrypt
fs-enc decrypt --key $key --file ./encfs/encrypted-file.txt
```

Writing encrypted data to a cloud store, 
The following example requires the appropriate driver s3fs in this case installed and AWS env variables configured

```bash
export AWS_PROFILE=xxxxxx
pip install -U s3fs
echo "This is sensitive data" | fs-enc encrypt --key $key  --file s3://<some-bucket>/encrypted-file.txt 
fs-enc decrypt --key $key --file s3://<some-bucket>/encrypted-file.txt 
```

## Development

If you'd like to contribute or modify the code, you can set up the project for development using Poetry.

### Setting Up for Development

1. Clone the repository:

   ```bash
   git clone https://github.com/thevgergroup/fsspec-encrypted.git
   cd fsspec-encrypted
   ```

2. Install the dependencies using Poetry:

   ```bash
   poetry install
   ```

3. After installation, any changes you make to the code will be automatically reflected when running the project.

### Running Tests

The project uses `pytest` for testing. To run the test suite, simply use:

```bash
poetry run pytest
```
