import pandas as pd
from fsspec_encrypted.fs_enc_cli import generate_key
import argparse

# Your encryption key
encryption_key = generate_key(passphrase="my_secret_passphrase", salt=b"12345432")


def read_from_s3(bucket):
    
    # Use AWS_PROFILE or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env variables to authenticate with AWS
    df = pd.read_csv(f'enc://s3://{bucket}/encrypted-file.csv', storage_options={"encryption_key": encryption_key})

    print(df)
    

if __name__ == "__main__":
    
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", help="Name of the S3 bucket")
    args = parser.parse_args()
    read_from_s3(args.bucket)

