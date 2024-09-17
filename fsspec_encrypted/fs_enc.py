from functools import partial
import fsspec
from fsspec.core import split_protocol
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom
from typing import IO, AnyStr, Optional, Text
import io
import os
from base64 import b64encode, b64decode

BLOCK_SIZE = 16  # AES block size in bytes


class EncryptedFS(fsspec.AbstractFileSystem):
    """
    A file system implementation for encrypted files.
    This class provides methods for encrypting and decrypting data, as well as reading and writing encrypted files.
    Args:
        encryption_key (str): The encryption key used for encrypting and decrypting the data.
    Attributes:
        protocol (str): The protocol used to register this filesystem.
    Methods:
        derive_key(passphrase: AnyStr, salt: bytes) -> bytes:
            Derives a key from a passphrase and salt.
        str_to_key(key_str: str) -> bytes:
            Converts a key string to bytes.
        key_to_str(key: bytes) -> str:
            Converts a key bytes to a string.
        determine_filesystem(path: str) -> Tuple[fsspec.AbstractFileSystem, str]:
            Determines the filesystem and path based on the given path.
        encrypt(data: bytes) -> bytes:
            Encrypts the data using AES-CBC and PKCS7 padding.
        decrypt(data: bytes) -> bytes:
            Decrypts the data using AES-CBC and PKCS7 unpadding.
        writebytes(path: str, data: bytes) -> None:
            Writes encrypted data to the file.
        writetext(path: Text, contents: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
            Writes text to the file.
        readbytes(path: str, size: int = -1) -> bytes:
            Reads and decrypts the content of the file.
        readtext(path: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> Text:
            Reads and decrypts the text content of the file.
        appendbytes(path: str, data: bytes) -> None:
            Appends encrypted data to the file.
        appendtext(path: Text, text: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
            Appends text to the file.
        openbin(path: str, mode: str = "rb", buffering: int = -1, **kwargs) -> io.IOBase:
            Opens the file in binary mode.
        close() -> None:
            Closes the file.
        open(path: Text, mode: Text = "r", encoding: Optional[Text] = None, errors: Optional[Text] = None, newline: Text = "", **kwargs) -> IO[AnyStr]:
            Opens the file in the specified mode.
        desc(path: Text) -> Text:
            Returns a description of the filesystem for the given path.
    protocol = "enc"  # Register this filesystem under the "enc" protocol
    """

    def __init__(self, encryption_key: str, **kwargs):
        super().__init__(**kwargs)
        
        self.key = encryption_key

    @classmethod
    def derive_key(cls, passphrase: AnyStr, salt: bytes) -> bytes:
        if isinstance(passphrase, str):
            passphrase = passphrase.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 requires 32 bytes
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(passphrase)

    @classmethod
    def str_to_key(cls, key_str: str) -> bytes:
        return b64decode(key_str)
    
    @classmethod
    def key_to_str(cls, key: bytes) -> str:
        return b64encode(key).decode()
    
    def determine_filesystem(self, path: str):
        protocol, _ = split_protocol(path)
        if protocol is None or protocol == "file".lower():
            fs = fsspec.filesystem('file', auto_mkdir=True)
            path = os.path.abspath(path)
        else:
            fs = fsspec.filesystem(protocol)
        return fs, path

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt the entire data stream with AES-CBC and PKCS7 padding.
        A new IV is generated for each encryption operation.
        """
        iv = urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt the data stream with AES-CBC and PKCS7 unpadding.
        The IV is extracted from the first block of the encrypted data.
        """
        iv = data[:BLOCK_SIZE]
        encrypted_data = data[BLOCK_SIZE:]
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def writebytes(self, path: str, data: bytes):
        """
        Write encrypted data to the file, ensuring that all chunks are handled
        consistently.
        Buffer the entire data to ensure padding and encryption is consistent.
        """
        encrypted_data = self.encrypt(data)
        fs, full_path = self.determine_filesystem(path)
        with fs.open(full_path, "wb") as f:
            f.write(encrypted_data)
            
        

    def writetext(self, path: Text, contents: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.writebytes(path, contents.encode(encoding))

    def readbytes(self, path: str, size:int = -1) -> bytes:
        """
        Read and decrypt the entire content of the file, ensuring consistent decryption.
        """
        #print("***************")
        fs, full_path = self.determine_filesystem(path)
        with fs.open(full_path, "rb") as f:
            encrypted_data = f.read()
            by = self.decrypt(encrypted_data)
            #print(by)
            return by
        

    def readtext(self, path: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> Text:
        return self.readbytes(path).decode(encoding)

    def appendbytes(self, path: str, data: bytes) -> None:
        """
        Buffer the existing file content, append the new data, and re-encrypt the entire file.
        TODO: This is not efficient for large files, but it is simple and secure. 
        Investigate AES-CTR mode.
        """
        
        fs, full_path = self.determine_filesystem(path)
        existing_data = b""
        
        if fs.exists(full_path):
            with fs.open(full_path, "rb") as f:
                existing_enc_data = f.read()
                if existing_enc_data:
                    existing_data = self.decrypt(existing_enc_data)
        
        combined_data = existing_data + data  # Append new plain text data to the existing plain text data
        encrypted_data = self.encrypt(combined_data)  # Re-encrypt everything
        
        with fs.open(full_path, "wb") as f:
            f.write(encrypted_data)
            

    def appendtext(self, path: Text, text: Text, encoding: Text = "utf-8", errors: Optional[Text] = None) -> None:
        self.appendbytes(path, text.encode(encoding))

    def openbin(self, path: str, mode: str = "rb", buffering: int = -1, **kwargs) -> io.IOBase:
        fs, full_path = self.determine_filesystem(path)
        raw_file = fs.open(full_path, mode)
        
        #raw_file.write = partial(self.appendbytes, path)
        #raw_file.read = partial(self.readbytes, path)
        #return raw_file
        
        # Separate the file object from the encryption functions, allowing the file object to be used directly
        # and to use buffered reads and writes.
        
        return _EncryptedFileWrapper(file_obj=raw_file, encrypt_func=self.encrypt, 
                                        decrypt_func=self.decrypt, encrypted_fs=self, 
                                        path=path, mode= mode)

    def close(self) -> None:
        #print("Closing EncryptedFS")
        pass
    
    def open(self, path: Text, mode: Text = "r", encoding: Optional[Text] = None, errors: Optional[Text] = None, newline: Text = "", **kwargs) -> IO[AnyStr]:
        if "b" in mode:
            return self.openbin(path, mode=mode)
        else:
            return partial(self.readtext if "r" in mode else self.writetext, path=path)

    def desc(self, path: Text) -> Text:
        return f"EncryptedFS for path {path}"


class _EncryptedFileWrapper(io.IOBase):
    """
    A wrapper class for encrypted file objects.
    Args:
        file_obj (io.IOBase): The underlying file object.
        encrypt_func (callable): The function used to encrypt data.
        decrypt_func (callable): The function used to decrypt data.
        encrypted_fs (EncryptedFS): The encrypted file system.
        path (str): The path to the file.
        mode (str): The mode in which the file is opened.
    Attributes:
        file_obj (io.IOBase): The underlying file object.
        encrypt_func (callable): The function used to encrypt data.
        decrypt_func (callable): The function used to decrypt data.
        encrypt_fs (EncryptedFS): The encrypted file system.
        path (str): The path to the file.
        mode (str): The mode in which the file is opened.
        _read_buffer (bytearray): The buffer used for reading data.
    Methods:
        write(data: bytes) -> int:
            Writes encrypted data to the file buffer, flush must be called on the file to write to media.
        read(size: int = -1) -> bytes:
            Reads and decrypts data from the file object.
        close() -> None:
            Closes the file object.
        flush() -> None:
            Flushes the write buffer and writes encrypted data to the file object.
        writable() -> bool:
            Returns True if the file object is writable, False otherwise.
        readable() -> bool:
            Returns True if the file object is readable, False otherwise.
    """
    def __init__(self, file_obj, encrypt_func, decrypt_func, encrypted_fs: EncryptedFS, path : str, mode: str):
        self.file_obj = file_obj
        self.encrypt_func = encrypt_func
        self.decrypt_func = decrypt_func
        self.encrypt_fs = encrypted_fs
        self.path = path
        self.mode = mode
        self._read_buffer = bytearray()

    def write(self, data: bytes) -> int:
        
        # Defer writing to the file until flush() is called
        
        if self.file_obj.writable():
            #encrypted_data = self.encrypt_func(data)
            #rt = self.file_obj.write(encrypted_data)
            #rt = self.encrypt_fs.appendbytes(self.path, data)
            self._read_buffer.extend(data)
            
            return None
        else:
            raise io.UnsupportedOperation("File not open for writing")

    def read(self, size: int = -1) -> bytes:
        if not self.file_obj.readable():
            raise io.UnsupportedOperation("File not open for reading")

        if size == -1:
            encrypted_data = self.file_obj.read()
            if encrypted_data == b"":
                return b""
            return self.decrypt_func(encrypted_data)

        #print("Reading from buffer")
        while len(self._read_buffer) < size:
            encrypted_chunk = self.file_obj.read()
            if encrypted_chunk == b"":
                break
            #print(encrypted_chunk)
            decrypted_chunk = self.decrypt_func(encrypted_chunk)
            self._read_buffer.extend(decrypted_chunk)

        result, self._read_buffer = self._read_buffer[:size], self._read_buffer[size:]
        return result

    def close(self) -> None:
        #print("Closing EncryptedFileWrapper")
        return self.file_obj.close()

    def flush(self) -> None:
        #print("Flushing EncryptedFileWrapper")
        #self.encrypt_fs.appendbytes(self.path, self._read_buffer)
        if self.file_obj.writable():
            self.encrypt_fs.appendbytes(self.path, self._read_buffer)
            self._read_buffer = b""
            return self.file_obj.flush()
        #self.file_obj.write(self._read_buffer)
        
        return self.file_obj.flush()

    def writable(self) -> bool:
        return self.file_obj.writable()

    def readable(self) -> bool:
        return self.file_obj.readable()


def fsspec_get_filesystem_class(protocol: str):
    if protocol == "enc":
        return EncryptedFS
