import pandas as pd
from fsspec_encrypted.fs_enc_cli import generate_key
from fsspec_encrypted.fs_enc import EncryptedFS
# Your encryption key
encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")
print("Encryption key:", EncryptedFS.key_to_str(encryption_key))

df = pd.read_csv('enc://./.encfs/encrypted-file.csv', storage_options={"encryption_key": encryption_key})

print(df)

