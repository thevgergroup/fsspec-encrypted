### Demo script

 
```sh
asciinema rec -t "fsspec-encrypted" -i 1 fs-enc-1.cast

figlet -w 300 fsspec-encrypted

fs-enc -h

# Lets generate a random key
key=$(fs-enc gen-key)
echo $key

#Lets encrypt data in a file locally
echo "This is sensitive data" | fs-enc encrypt --key $key  --file ./encfs/encrypted-file.txt 
cat ./encfs/encrypted-file.txt

# Lets decrypt it
fs-enc decrypt --key $key  --file ./encfs/encrypted-file.txt  

# Lets do the same thing on S3, showing the power of using fsspec
echo "This is sensitive data" | fs-enc encrypt --key $key  --file s3://fssec-test/encrypted-file.txt 
# Lets view it to verify
aws s3 cp s3://fssec-test/encrypted-file.txt -

# Lets decrypt it
fs-enc decrypt --key $key  --file s3://fssec-test/encrypted-file.txt  
```


