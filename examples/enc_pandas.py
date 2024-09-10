import pandas as pd
from fsspec_encrypted.fs_enc_cli import generate_key

# Your encryption key can be generated using the generate_key function
encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")

# Create a sample DataFrame
data = {
    'name': ['Alice', 'Bob', 'Charlie'],
    'age': [25, 30, 35]
}
df = pd.DataFrame(data)

# Open the encrypted file stream
# with fsspec.open('enc://./encfs/encrypted-file.csv', 'wb', protocol="enc", encryption_key=encryption_key) as f:
#     #df.to_csv(f, index=False)

df.to_csv('enc://./.encfs/encrypted-file.csv', index=False, storage_options={"encryption_key": encryption_key})

print("Data written to encrypted file with key:", encryption_key.decode())
