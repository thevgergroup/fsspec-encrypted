# fsspec-encrypted

**fsspec-encrypted** is a Python package that provides an encrypted filesystem layer using the `fsspec` interface. It allows users to transparently encrypt and decrypt files while maintaining compatibility with any underlying `fsspec`-compatible filesystem (e.g., local, S3, GCS, etc.).

This is a port of [fs-encrypted](https://github.com/thevgergroup/fs-encrypted) to [fsspec](https://github.com/fsspec/filesystem_spec/) mainly because of inactivity and possible abandonment of the underlying file system pyfilesystem2.

`fsspec-encrypted` is an AES encrypted driver for `fsspec`


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
enc_fs = fsspec.filesystem('enc', root_path='./encfs', encryption_key=encryption_key)

# Write some encrypted data to a file
enc_fs.writetext('example.txt', 'This is some encrypted text.')

# Read the encrypted data back from the file
print(enc_fs.readtext('example.txt'))
```

### S3 Filesystem Example

```python
import fsspec
from cryptography.fernet import Fernet

# Generate an encryption key
encryption_key = Fernet.generate_key()

# Use the encrypted filesystem on top of an S3 file system
enc_fs = fsspec.filesystem('enc', root_path='your-bucket', encryption_key=encryption_key, underlying_fs='s3')

# Write some encrypted data to S3
enc_fs.writetext('s3://your-bucket/example.txt', 'This is some encrypted text.')

# Read the encrypted data back from S3
print(enc_fs.readtext('s3://your-bucket/example.txt'))
```

### Other Filesystems

You can specify other `fsspec`-compatible filesystems (such as GCS, FTP, etc.) by passing the desired protocol as `underlying_fs` during initialization. If no `underlying_fs` is provided, it defaults to the local filesystem.

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
