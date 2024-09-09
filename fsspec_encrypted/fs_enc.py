import fsspec
from cryptography.fernet import Fernet
from functools import partial
from typing import AnyStr, BinaryIO, Optional, Text, IO
import os


class EncryptedFS(fsspec.AbstractFileSystem):
    protocol = "enc"  # Register this filesystem under the "enc" protocol

    def __init__(self, encryption_key: str, **kwargs):
        """
        Initialize EncryptedFS on top of any fsspec-compatible filesystem.

        :param encryption_key: Encryption key for the data.
        """
        super().__init__(**kwargs)
        self.encryption_key = encryption_key
        self.cipher_suite = Fernet(encryption_key)

    def determine_filesystem(self, path: str):
        """
        Determines the appropriate filesystem (e.g., local, S3) based on the path.
        Returns the filesystem and cleaned path.
        """
        if path.startswith("s3://"):
            fs = fsspec.filesystem('s3')
        elif path.startswith("gcs://"):
            fs = fsspec.filesystem('gcs')
        elif path.startswith("ftp://"):
            fs = fsspec.filesystem('ftp')
        else:
            # Default to local filesystem
            fs = fsspec.filesystem('file', auto_mkdir=True)
            # Ensure the path is absolute for local filesystems
            path = os.path.abspath(path)
        
        return fs, path

    def encrypt(self, data: bytes) -> bytes:
        return self.cipher_suite.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        # Handle encrypted chunks (if appended)
        lines = data.split(b"==")
        decrypted_data = b""
        for line in lines:
            line += b"=="
            if line == b"==":
                continue
            decrypted_data += self.cipher_suite.decrypt(line)
        return decrypted_data

    def writebytes(self, path: str, data: bytes):
        encrypted_data = self.encrypt(data)
        fs, full_path = self.determine_filesystem(path)
        with fs.open(full_path, "wb") as f:
            f.write(encrypted_data)

    def writetext(self, path: Text, contents: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.writebytes(path, contents.encode(encoding))

    def readbytes(self, path: str) -> bytes:
        fs, full_path = self.determine_filesystem(path)
        with fs.open(full_path, "rb") as f:
            encrypted_data = f.read()
        return self.decrypt(encrypted_data)

    def readtext(self, path: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> Text:
        return self.readbytes(path).decode(encoding)

    def appendbytes(self, path: str, data: bytes) -> None:
        encrypted_data = self.encrypt(data)
        fs, full_path = self.determine_filesystem(path)
        with fs.open(full_path, "ab") as f:
            f.write(encrypted_data)

    def appendtext(self, path: Text, text: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.appendbytes(path, text.encode(encoding))

    def openbin(self, path: Text, mode: Text = "rb", buffering: int = -1, **kwargs) -> BinaryIO:
        fs, full_path = self.determine_filesystem(path)
        return fs.open(full_path, mode)

    def open(self, path: Text, mode: Text = "r", encoding: Optional[Text] = None, errors: Optional[Text] = None, newline: Text = "", **kwargs) -> IO[AnyStr]:
        if "b" in mode:
            return self.openbin(path, mode=mode)
        else:
            return partial(self.readtext if "r" in mode else self.writetext, path=path)

    def desc(self, path: Text) -> Text:
        return f"EncryptedFS for path {path}"




# Register the "enc" filesystem to be used with fsspec
def fsspec_get_filesystem_class(protocol: str):
    if protocol == "enc":
        return EncryptedFS
