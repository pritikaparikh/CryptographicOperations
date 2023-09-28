import argparse
import rsa


#sign message and write signature block to current directory
def rsa_sign(message, txt_key, hash_fn):
    print('Signing...')
    privatekey = rsa.PrivateKey.load_pkcs1(txt_key.encode())
    signature_block = rsa.sign(message, privatekey, hash_fn)
    print('RSA signed')

    with open('signature_block.txt', 'wb') as o:
        o.write(signature_block)
    exit(0)

#verify signature
def rsa_verify(message, signature, txt_key):
    print('Verifying...')
    publickey = rsa.PublicKey.load_pkcs1(txt_key.encode())
    verified_hash_fn = rsa.verify(message, signature, publickey)
    print('Verified')
    print(f'Hash function used: {str(verified_hash_fn)}')
    exit(0)


#generate key pairs and write them to current directory
def keygen():
    publickey, privatekey = rsa.newkeys(2048)
    with open('privatekey.pem', 'wt') as o:
        o.write(privatekey._save_pkcs1_pem().decode())

    with open('publickey.pem', 'wt') as o:
        o.write(publickey._save_pkcs1_pem().decode())

    exit(0)


#encrypt plaintext to be signed and write encrypted file to current directory
def encrypt(plaintext, txt_key):
    publickey = rsa.PublicKey.load_pkcs1(txt_key.encode())
    cipher = rsa.encrypt(plaintext.encode(), publickey)
    with open('cipher.sh', 'wb') as o:
        o.write(cipher)
    print('Plain-text file encrypted')
    exit(0)

#decrypt plaintext
def decrypt(cipher, txt_key):
    privatekey = rsa.PrivateKey.load_pkcs1(txt_key.encode())
    plain_txt = rsa.decrypt(cipher, privatekey).decode()
    print('Decrypted message: \n' + str(plain_txt))
    # with open('plain_txt.txt', 'wt') as o:
    #     o.write(plain_txt)
    exit(0)


#sourcery skip: raise-specific-error
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # input params
    parser.add_argument('--key', help='Private or Public Key file', required=False)
    parser.add_argument('--hash_function', help='the hash function to use, default is SHA-1', default='SHA-1')
    parser.add_argument('--signature', help='the file that contains the signature', required=False)
    parser.add_argument('--message', help='the message to sign or that has been signed', required=False)
    # actions
    parser.add_argument('--keygen', help='if True, instructs programme to generate an RSA key pair', default=False, type=bool)
    parser.add_argument('--sign', help='if True, instructs programme to sign', default=False, type=bool)
    parser.add_argument('--verify', help='if True, instructs programme to verify', default=False, type=bool)
    parser.add_argument('--encrypt', help='if True, instructs programme to encrypt', default=False, type=bool)
    parser.add_argument('--decrypt', help='if True, instructs programme to decrypt', default=False, type=bool)

    args = parser.parse_args()
    print(args)

    try:
        if args.keygen:
            keygen()

        #reads in key file
        with open(args.key, 'r') as f:
            key = f.read()

        if args.encrypt:
            with open(args.message, 'r') as f:
                msg = f.read()
            encrypt(msg, key)
        if args.decrypt:
            with open(args.message, 'rb') as f:
                msg = f.read()
            decrypt(msg, key)

        #verify if hash function is valid
        hash_fn = args.hash_function
        if hash_fn not in ['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']:
            raise Exception('Invalid hash scheme')
        #reads in message
        with open(args.message, 'rb') as f:
            msg = f.read()

        if args.sign:
            rsa_sign(msg, key, hash_fn)
        if args.verify:
            with open(args.signature, 'rb') as f:
                bytes_signature = f.read()
            rsa_verify(msg, bytes_signature, key)

    except Exception:
        print('Invalid Input Parameters')