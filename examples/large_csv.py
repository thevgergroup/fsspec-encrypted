import io
from time import sleep
import pandas as pd
import numpy as np
import fsspec
from fsspec_encrypted.fs_enc_cli import generate_key
from fsspec_encrypted.fs_enc import EncryptedFS

encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")

print("key: ", EncryptedFS.key_to_str(encryption_key))

# Set the desired number of rows and columns
num_rows = 1000000  # 1 million rows
num_cols = 30 

# Create a dictionary to hold the data
data = {}
for col in range(num_cols):
    data[f'col_{col+1}'] = np.random.randint(0, 100, num_rows)

# Create the dataframe
df = pd.DataFrame(data)

df = pd.DataFrame(data)

print(df.shape)
print(df.head())
# Save the dataframe to a CSV file
print("Writing to encrypted file")
df.to_csv('enc://./.encfs/large_random_data.csv', index=False, storage_options={"encryption_key": encryption_key})
print("Data written to encrypted file")

print("Reading from encrypted file")
df2 = pd.read_csv('enc://./.encfs/large_random_data.csv', storage_options={"encryption_key": encryption_key})
print("Data read from encrypted file")

print(df2.shape)

print(df2.head())

# Alternatively you can use the following code to read the encrypted file using fsspec and Pandas

# Read the encrypted CSV file using fsspec and Pandas
# Step 1: Open the encrypted file using fsspec
#with fsspec.open('enc://./.encfs/large_random_data.csv', 'rb', encryption_key=encryption_key) as f:
#     # Step 2: Read the decrypted content from the file
#    decrypted_content = bytes(f.read()).decode()
#     print("here")
#     # Step 3: Use io.StringIO to create a file-like object that Pandas can read
#    decrypted_file = io.StringIO(decrypted_content)
#     print("here 2") 
#     print(decrypted_content)
#     # Step 4: Use Pandas to read the decrypted content
#    df2 = pd.read_csv(decrypted_file)

