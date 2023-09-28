# CryptographicOperations
Cryptographic Operations in Python
# Build
To build the app make sure rsa and argparse are installed. These can be easily installed using pip.

```
pip install rsa
```
```
pip install argparse
```

I chose to work with the rsa package because it is lightweight and easy to use/understand while providing all the desired functionality.

# Usage
The program can perfom five tasks. To run call one of the following:

Key Generation
```
python openssl.py --keygen True
```
Generates the public and private keys needed for encryption, decryption, signing, and verification.

Encryption
```
python openssl.py --encrypt True --message (plaintext file) --key (public key)
```
encrypts the plaintext message.

Decryption
```
python openssl.py --decrypt True --message (encrypted file) --key (private key)
```
Decrypts the encrypted message.

Signing
```
python openssl.py --sign True --message (unsigned file) --key (private key)
```
Generates a digital signature for the message.

Signing has an optional parameter --hash_function which may be specified to use one of the following hash functions: 'MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'. The default is 'SHA-1'.

Verification
```
python openssl.py --verify True --message (signed file) --signature (signature block) --key (public key)
```
Verifies the digital signature of the message.
python openssl.py --verify True --message (signed file) --signature (signature block) --key (public key)

Verifies the digital signature of the message.
