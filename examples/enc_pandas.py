import pandas as pd
from fsspec_encrypted.fs_enc_cli import generate_key
from base64 import b64encode
from fsspec_encrypted.fs_enc import EncryptedFS

# Your encryption key can be generated using the generate_key function
encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")

# Create a sample DataFrame
data = {
    'name': ['Alice', 'Bob', 'Charlie'],
    'age': [25, 30, 35]
}
df = pd.DataFrame(data)

df.to_csv('enc://./.encfs/encrypted-file.csv', index=False, storage_options={"encryption_key": encryption_key})

print("Data written to encrypted file with key:", EncryptedFS.key_to_str(encryption_key))

df2 = pd.read_csv('enc://./.encfs/encrypted-file.csv', storage_options={"encryption_key": encryption_key})
