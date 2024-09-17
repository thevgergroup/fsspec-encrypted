import pytest
import fsspec
from cryptography.fernet import Fernet
import os
import string
import random
from fsspec_encrypted.fs_enc import EncryptedFS
from fsspec_encrypted.fs_enc_cli import generate_key, generate_key_from_passphrase, encrypt_and_write, decrypt_and_read

@pytest.fixture
def encryption_key():
    """Fixture to generate an encryption key for testing."""
    passphrase = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
    salt = os.urandom(16)
    return EncryptedFS.derive_key(passphrase, salt)

@pytest.fixture
def enc_fs(encryption_key):
    """Fixture to create a temporary encrypted filesystem with default local filesystem."""
    fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    return fs

def test_generate_key():
    """Test the generation of an encryption key."""
    key = generate_key()
    assert isinstance(key, bytes)

def test_generate_key_from_passphrase():
    """Test the generation of an encryption key from a passphrase."""
    passphrase = "testpass"
    salt = os.urandom(16)
    key, salt = generate_key_from_passphrase(passphrase, salt)
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)

def test_encrypt_and_write(encryption_key, tmp_path):
    """Test the encryption and writing of data."""
    test_file = tmp_path / "test.txt"
    input_data = "This is a test message."
    #encryption_key = Fernet.generate_key()
    encrypt_and_write(encryption_key, str(test_file), input_data)
    fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    result = fs.readtext(str(test_file))
    assert result == input_data

def test_decrypt_and_read(encryption_key, tmp_path):
    """Test the decryption and reading of data."""
    test_file = tmp_path / "test.txt"
    input_data = "This is a test message."
    #encryption_key = Fernet.generate_key()
    fs = fsspec.filesystem('enc', encryption_key=encryption_key)
    fs.writetext(str(test_file), input_data)
    decrypted_data = decrypt_and_read(encryption_key, str(test_file))
    assert decrypted_data == input_data