import pytest
import fsspec
from cryptography.fernet import Fernet
import os


@pytest.fixture
def encryption_key():
    """Fixture to generate an encryption key for testing."""
    return Fernet.generate_key()


@pytest.fixture
def enc_fs(tmp_path, encryption_key):
    """Fixture to create a temporary encrypted filesystem with default local filesystem."""
    root_path = tmp_path / "encfs"
    root_path.mkdir()
    
    # Initialize the encrypted filesystem (defaults to local 'file' filesystem)
    fs = fsspec.filesystem('enc', root_path=str(root_path), encryption_key=encryption_key)
    
    return fs


def test_write_and_read_text(enc_fs):
    """Test that writing and reading encrypted text works."""
    enc_fs.writetext("test.txt", "This is a test message.")
    
    result = enc_fs.readtext("test.txt")
    assert result == "This is a test message."


def test_write_and_read_bytes(enc_fs):
    """Test that writing and reading encrypted bytes works."""
    data = b"Some binary data"
    enc_fs.writebytes("binary.dat", data)
    
    result = enc_fs.readbytes("binary.dat")
    assert result == data


def test_append_text(enc_fs):
    """Test that appending encrypted text works."""
    enc_fs.writetext("append.txt", "Line 1.\n")
    enc_fs.appendtext("append.txt", "Line 2.")
    
    result = enc_fs.readtext("append.txt")
    assert result == "Line 1.\nLine 2."


def test_append_bytes(enc_fs):
    """Test that appending encrypted bytes works."""
    enc_fs.writebytes("append.dat", b"Part 1, ")
    enc_fs.appendbytes("append.dat", b"Part 2")
    
    result = enc_fs.readbytes("append.dat")
    assert result == b"Part 1, Part 2"


def test_encrypted_data_is_different(enc_fs, tmp_path):
    """Test that the encrypted data stored is different from the plaintext."""
    plaintext = "Sensitive information."
    
    enc_fs.writetext("secret.txt", plaintext)
    
    # Directly accessing the encrypted file in the tmp_path directory
    with enc_fs.fs.open(tmp_path / "encfs" / "secret.txt", "rb") as f:
        encrypted_data = f.read()
    
    assert encrypted_data != plaintext.encode()


def test_encrypted_and_decrypted_data(enc_fs):
    """Test that the data is correctly encrypted and decrypted."""
    original_data = b"Encrypt this data."
    
    enc_fs.writebytes("encrypt.dat", original_data)
    decrypted_data = enc_fs.readbytes("encrypt.dat")
    
    assert decrypted_data == original_data
