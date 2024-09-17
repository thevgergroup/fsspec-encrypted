fsspec-encrypted
================

``fsspec-encrypted`` is a package that provides an encrypted filesystem
for use with Python. It’s built on
`fsspec <https://filesystem-spec.readthedocs.io/en/latest/>`__ making it
compatible with Cloud Services like S3, GCS, Azure Blob Service / Data
Lake etc. As well as bringing encryption to Pandas Data Frames.

It allows users to transparently encrypt and decrypt files while
maintaining compatibility with any underlying ``fsspec``-compatible
filesystem (e.g., local, S3, GCS, etc.).

-  `fsspec-encrypted <#fsspec-encrypted>`__

   -  `Note <#note>`__
   -  `Keys <#keys>`__
   -  `Features <#features>`__
   -  `Application <#application>`__
   -  `Installation <#installation>`__
   -  `Usage <#usage>`__

      -  `Local Filesystem Example <#local-filesystem-example>`__
      -  `Pandas compatibility <#pandas-compatibility>`__
      -  `S3 Filesystem Example <#s3-filesystem-example>`__
      -  `Other Filesystems <#other-filesystems>`__

   -  `CLI <#cli>`__

      -  `Generate an Encryption Key <#generate-an-encryption-key>`__
      -  `What is a Salt? <#what-is-a-salt>`__
      -  `Encrypt data from stdin and write it to a
         file <#encrypt-data-from-stdin-and-write-it-to-a-file>`__

   -  `Development <#development>`__

      -  `Setting Up for Development <#setting-up-for-development>`__
      -  `Running Tests <#running-tests>`__

Note
----

This supersedes
`fs-encrypted <https://github.com/thevgergroup/fs-encrypted>`__ as it
appears pyfilesystem2 is no longer maintained. So we are switching to
`fsspec <https://github.com/fsspec/filesystem_spec/>`__ which has a
broad level of adoption.

``fsspec-encrypted`` is an AES-256 CBC encrypted driver for ``fsspec``
The entire file is buffered to memory before written to disk with the
pandas to\_\* methods, this is to reduce time spent on decrypting and
re-encrypting by chunk.

Our roadmap will be to switch to AES-CTR to allow for streaming
encryption, which will reduce the need for a larger memory footprint.

Keys
----

We use a keys, ensure you store the keys securely!!!! A lost key means
lost data!

Keys are natively bytes, and should be base64 encoded / decoded, use the
methods EncryptedFS.key_to_str and EncryptedFS.str_to_key, for storing,
transmitting, and especially copying + pasting. These helper methods are
named as I couldn’t remember if I should encode or decode - so write
once and forget.

e.g.

.. code:: python

   from fsspec_encrypted.fs_enc_cli import generate_key
   from fsspec_encrypted.fs_enc import EncryptedFS

   # Your encryption key
   encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")
   print("Encryption key:", EncryptedFS.key_to_str(encryption_key))

Features
--------

-  **Encryption on top of any filesystem**: Works with any
   ``fsspec``-supported filesystem (e.g., local, S3, GCS, FTP, Azure).
-  **Automatic encryption and decryption**: Data is automatically
   encrypted during writes and decrypted during reads.
-  **CLI**: Provides for easy scripting and key generation
-  **Simple and flexible**: Minimal setup required with flexible file
   system options.

Application
-----------

Applications that may require sensitive data storage should use an
encrypted file system. By providing a layer of abstraction on top of the
encryption our hope is to make it safer to store this data.

PII / PHI \* Print Billing systems \* Insurance services / Identity
cards \* Data Transfer \* Secure distributed configuration

Installation
------------

You can install ``fsspec-encrypted`` via pip from PyPI:

.. code:: bash

   pip install fsspec-encrypted

Usage
-----

Here’s a simple example of using ``fsspec-encrypted`` to create an
encrypted filesystem layer on top of a local filesystem (default) and
perform basic read and write operations.

Local Filesystem Example
~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   import fsspec
   from fsspec_encrypted.fs_enc_cli import generate_key

   # Generate an encryption key
   encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")

   # Create an EncryptedFS instance (local filesystem is the default)
   enc_fs = fsspec.filesystem('enc', encryption_key=encryption_key)

   # Write some encrypted data to a file
   enc_fs.writetext('./encfs/example.txt', 'This is some encrypted text.')

   # Read the encrypted data back from the file
   print(enc_fs.readtext('./encfs/example.txt'))

Pandas compatibility
~~~~~~~~~~~~~~~~~~~~

Pandas uses ``fsspec`` under the hood, which lets you using the read /
to methods to encrypt data Additional note, we are using the
generate_key here with a passphrase and salt to allow for reusable key

.. code:: python

   import pandas as pd
   from fsspec_encrypted.fs_enc_cli import generate_key

   # Your encryption key
   encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")

   # Create a sample DataFrame
   data = {
       'name': ['Alice', 'Bob', 'Charlie'],
       'age': [25, 30, 35]
   }
   df = pd.DataFrame(data)

   # This encrypts the file to disk
   df.to_csv('enc://./encfs/encrypted-file.csv', index=False, storage_options={"encryption_key": encryption_key})

   print("Data written to encrypted file with key:", encryption_key.decode())

   # Read and decrypt the file
   df2 = pd.read_csv('enc://./encfs/encrypted-file.csv', storage_options={"encryption_key": encryption_key})

   print(df2)

S3 Filesystem Example
~~~~~~~~~~~~~~~~~~~~~

This is an example of using encryption on top of other file systems,
where we wrap S3 and encrypt or decrypt as required.

.. code:: python

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

   # This can also be done by wrapping the filesystem
   bucket="some-bucket"
   df = pd.read_csv(f'enc://s3://{bucket}/encrypted-file.csv', storage_options={"encryption_key": encryption_key})

Other Filesystems
~~~~~~~~~~~~~~~~~

``fsspec-encrypted`` automatically determines the filesystem type based
on the file path.

For example, if the path starts with s3://, it will use S3; otherwise,
it defaults to the local filesystem. It supports any fsspec-compatible
filesystem (e.g., GCS, FTP).

For wrapping the filesystem we can use ``enc://<other-file-system>://``

CLI
---

``fsspec-encrypted`` also includes a command-line interface (CLI) for
encrypting and decrypting files.

This allows a simple ability to encrypt and decrypt files without code
|asciicast|

Generate an Encryption Key
~~~~~~~~~~~~~~~~~~~~~~~~~~

Store your keys appropriately - a secrets manager is an ideal solution!

.. code:: bash

   # Generate a random key
   # CRITICAL STORE THE KEY SOMEWHERE SECURE
   key=$(fs-enc gen-key)

If you want to generate a key based on a passphrase and salt

.. code:: bash

   fs-enc gen-key --passphrase 'hello world' --salt 12345432

What is a Salt?
~~~~~~~~~~~~~~~

A salt is a random 16 byte value used during the key derivation process
to ensure that even if two people use the same passphrase, the derived
encryption keys will be different. The salt is not a secret, but it
should be unique and random for each encryption.

When encrypting data, the salt is usually stored alongside the encrypted
data so that it can be used again during decryption to derive the same
encryption key from the passphrase.

Encrypt data from stdin and write it to a file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: bash

   # Encrypt and store locally
   echo "This is sensitive data" | fs-enc encrypt --key $key --file ./encfs/encrypted-file.txt
   # Decrypt
   fs-enc decrypt --key $key --file ./encfs/encrypted-file.txt

Writing encrypted data to a cloud store, The following example requires
the appropriate driver s3fs in this case installed and AWS env variables
configured

.. code:: bash

   export AWS_PROFILE=xxxxxx
   pip install -U s3fs
   echo "This is sensitive data" | fs-enc encrypt --key $key  --file s3://<some-bucket>/encrypted-file.txt 
   fs-enc decrypt --key $key --file s3://<some-bucket>/encrypted-file.txt 

Development
-----------

If you’d like to contribute or modify the code, you can set up the
project for development using Poetry.

Setting Up for Development
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Clone the repository:

   .. code:: bash

      git clone https://github.com/thevgergroup/fsspec-encrypted.git
      cd fsspec-encrypted

2. Install the dependencies using Poetry:

   .. code:: bash

      poetry install

3. After installation, any changes you make to the code will be
   automatically reflected when running the project.

Running Tests
~~~~~~~~~~~~~

The project uses ``pytest`` for testing. To run the test suite, simply
use:

.. code:: bash

   poetry run pytest

.. |asciicast| image:: https://asciinema.org/a/hwpcCH1r1CM7ezNU4fM6wgKiY.svg
   :target: https://asciinema.org/a/hwpcCH1r1CM7ezNU4fM6wgKiY
