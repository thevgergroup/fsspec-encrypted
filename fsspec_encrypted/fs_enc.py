import fsspec
from fsspec.core import split_protocol
from cryptography.fernet import Fernet
from functools import partial
from typing import AnyStr, BinaryIO, Optional, Text, IO
import os
import io

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
        
        Ideally this should be a protocol handler for multiple protocols.
        e.g.
        s3+enc://bucket/key 
        gs+enc://bucket/key
        etc...
        
        However that's not available in fsspec yet.
        
        """
        protocol, _ = split_protocol(path)
        
        if protocol is None or protocol == "file".lower():
            # Default to local filesystem
            fs = fsspec.filesystem('file', auto_mkdir=True)
            # Ensure the path is absolute for local filesystems
            path = os.path.abspath(path)
        else:
            fs = fsspec.filesystem(protocol)
        
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

    def openbin(self, path: str, mode: str = "rb", buffering: int = -1, **kwargs) -> io.IOBase:
        """
        Override openbin to ensure encrypted/decrypted streams are returned.
        This wraps the underlying filesystem's file object to apply encryption or decryption.
        """
        fs, full_path = self.determine_filesystem(path)
        raw_file = fs.open(full_path, mode)
        return _EncryptedFileWrapper(raw_file, self.cipher_suite, mode)

    def open(self, path: Text, mode: Text = "r", encoding: Optional[Text] = None, errors: Optional[Text] = None, newline: Text = "", **kwargs) -> IO[AnyStr]:
        if "b" in mode:
            return self.openbin(path, mode=mode)
        else:
            return partial(self.readtext if "r" in mode else self.writetext, path=path)

    def desc(self, path: Text) -> Text:
        return f"EncryptedFS for path {path}"



class _EncryptedFileWrapper(io.IOBase):
    """
    Required to wrap the underlying file object to apply encryption/decryption.
    Needed for pandas to work with encrypted files.
    Or anything that uses the file object directly. 
    e.g.
    
    with open('enc://./encfs/encrypted-file.csv', 'rb') as f:
        print(f.read())
        
    """
    def __init__(self, file_obj, cipher_suite, mode: str):
        self.file_obj = file_obj
        self.cipher_suite = cipher_suite
        self.mode = mode

    def write(self, data: bytes) -> int:
        """Encrypt and write data."""
        if self.file_obj.writable():
            encrypted_data = self.cipher_suite.encrypt(data)
            return self.file_obj.write(encrypted_data)
        else:
            raise io.UnsupportedOperation("File not open for writing")

    def read(self, size: int = -1) -> bytes:
        """Read and decrypt data."""
        if self.file_obj.readable():
            encrypted_data = self.file_obj.read(size)
            if encrypted_data == b"":
                return b""  # Return empty if no data is read
            return self.cipher_suite.decrypt(encrypted_data)
        else:
            raise io.UnsupportedOperation("File not open for reading")

    def close(self) -> None:
        return self.file_obj.close()

    def flush(self) -> None:
        return self.file_obj.flush()

    def writable(self) -> bool:
        return self.file_obj.writable()

    def readable(self) -> bool:
        return self.file_obj.readable()


#fsspec.register_implementation("env", EncryptedFS)
# Register the "enc" filesystem to be used with fsspec
def fsspec_get_filesystem_class(protocol: str):
    if protocol == "enc":
        return EncryptedFS
