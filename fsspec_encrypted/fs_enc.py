import fsspec
from cryptography.fernet import Fernet
from functools import partial
from typing import AnyStr, BinaryIO, Optional, Text, IO


class EncryptedFS(fsspec.AbstractFileSystem):
    protocol = "enc"  # Register this filesystem under the "enc" protocol

    def __init__(self, root_path: str, encryption_key: str, underlying_fs: str = "file", **kwargs):
        """
        Initialize EncryptedFS on top of any fsspec-compatible filesystem.

        :param root_path: The root path of the encrypted storage.
        :param encryption_key: Encryption key for the data.
        :param underlying_fs: The protocol for the underlying filesystem (defaults to 'file').
        """
        super().__init__(**kwargs)
        self.encryption_key = encryption_key
        self.cipher_suite = Fernet(encryption_key)
        # Initialize the underlying filesystem (defaults to local 'file')
        #self.fs = fsspec.filesystem(underlying_fs, auto_mkdir=True)
        # Use different filesystem initialization depending on the type of filesystem
        if underlying_fs == "file":
            self.fs = fsspec.filesystem(underlying_fs, auto_mkdir=True)  # Only local filesystems need auto_mkdir
        else:
            self.fs = fsspec.filesystem(underlying_fs)  # For S3, GCS, and others, we omit auto_mkdir

        self.root_path = root_path

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
        with self.fs.open(f"{self.root_path}/{path}", "wb") as f:
            f.write(encrypted_data)

    def writetext(self, path: Text, contents: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.writebytes(path, contents.encode(encoding))

    def readbytes(self, path: str) -> bytes:
        with self.fs.open(f"{self.root_path}/{path}", "rb") as f:
            encrypted_data = f.read()
        return self.decrypt(encrypted_data)

    def readtext(self, path: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> Text:
        return self.readbytes(path).decode(encoding)

    def appendbytes(self, path: str, data: bytes) -> None:
        encrypted_data = self.encrypt(data)
        with self.fs.open(f"{self.root_path}/{path}", "ab") as f:
            f.write(encrypted_data)

    def appendtext(self, path: Text, text: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.appendbytes(path, text.encode(encoding))

    def openbin(self, path: Text, mode: Text = "rb", buffering: int = -1, **kwargs) -> BinaryIO:
        return self.fs.open(f"{self.root_path}/{path}", mode)

    def open(self, path: Text, mode: Text = "r", encoding: Optional[Text] = None, errors: Optional[Text] = None, newline: Text = "", **kwargs) -> IO[AnyStr]:
        if "b" in mode:
            return self.openbin(path, mode=mode)
        else:
            return partial(self.readtext if "r" in mode else self.writetext, path=path)

    def desc(self, path: Text) -> Text:
        return f"EncryptedFS for path {self.root_path}/{path}"


# Register the "enc" filesystem to be used with fsspec
def fsspec_get_filesystem_class(protocol: str):
    if protocol == "enc":
        return EncryptedFS
