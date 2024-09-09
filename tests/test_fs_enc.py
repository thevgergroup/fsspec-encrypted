import pytest
import fsspec
from cryptography.fernet import Fernet
import os


@pytest.fixture
def encryption_key():
    """Fixture to generate an encryption key for testing."""
    return Fernet.generate_key()


@pytest.fixture
def enc_fs(encryption_key):
    """Fixture to create a temporary encrypted filesystem with default local filesystem."""
    # Initialize the encrypted filesystem (defaults to local 'file' filesystem)
    fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    return fs


def test_write_and_read_text(enc_fs, tmp_path):
    """Test that writing and reading encrypted text works."""
    # Use the tmp_path for storing the test files
    test_file = tmp_path / "test.txt"
    enc_fs.writetext(str(test_file), "This is a test message.")
    
    result = enc_fs.readtext(str(test_file))
    assert result == "This is a test message."


def test_write_and_read_bytes(enc_fs, tmp_path):
    """Test that writing and reading encrypted bytes works."""
    test_file = tmp_path / "binary.dat"
    data = b"Some binary data"
    enc_fs.writebytes(str(test_file), data)
    
    result = enc_fs.readbytes(str(test_file))
    assert result == data


def test_append_text(enc_fs, tmp_path):
    """Test that appending encrypted text works."""
    test_file = tmp_path / "append.txt"
    enc_fs.writetext(str(test_file), "Line 1.\n")
    enc_fs.appendtext(str(test_file), "Line 2.")
    
    result = enc_fs.readtext(str(test_file))
    assert result == "Line 1.\nLine 2."


def test_append_bytes(enc_fs, tmp_path):
    """Test that appending encrypted bytes works."""
    test_file = tmp_path / "append.dat"
    enc_fs.writebytes(str(test_file), b"Part 1, ")
    enc_fs.appendbytes(str(test_file), b"Part 2")
    
    result = enc_fs.readbytes(str(test_file))
    assert result == b"Part 1, Part 2"


def test_encrypted_data_is_different(enc_fs, tmp_path):
    """Test that the encrypted data stored is different from the plaintext."""
    plaintext = "Sensitive information."
    test_file = tmp_path / "secret.txt"
    
    enc_fs.writetext(str(test_file), plaintext)
    
    # Read the raw encrypted data
    with open(test_file, "rb") as f:
        encrypted_data = f.read()
    
    assert encrypted_data != plaintext.encode()


def test_encrypted_and_decrypted_data(enc_fs, tmp_path):
    """Test that the data is correctly encrypted and decrypted."""
    test_file = tmp_path / "encrypt.dat"
    original_data = b"Encrypt this data."
    
    enc_fs.writebytes(str(test_file), original_data)
    decrypted_data = enc_fs.readbytes(str(test_file))
    
    assert decrypted_data == original_data
