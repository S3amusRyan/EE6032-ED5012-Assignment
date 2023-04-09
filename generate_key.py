# OUTDATED PYCRYPTODOME IMPLEMENTATION

# from Crypto.PublicKey import RSA as rsa

# for instance in {"A", "B", "C", "S", "PUBCERT"}:

#     # Generate keypair
#     key = rsa.generate(2048)

#     # Write Private key
#     f = open('keys/privkey_'+instance+'.pem', 'wb')
#     f.write(key.export_key('PEM'))
#     f.close()

#     # Write Public key
#     f = open('keys/pubkey_'+instance+'.pem', 'wb')
#     f.write(key.public_key().export_key('PEM'))
#     f.close()



# Cryptography implmenetation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 RSA Key Generator',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-o', '--out', type=str, nargs='+')

args = parser.parse_args()

for outfile in args.out:
    key_prv = rsa.generate_private_key(65537, 2048)
    pem_prv = key_prv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    open(outfile, 'wb').write(pem_prv)
    print("Written private key to '", outfile, "'")

    key_pub = key_prv.public_key()
    pem_pub = key_pub.public_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    open(outfile+".pub", 'wb').write(pem_pub)
    print("Written public key to '", outfile, ".pub'")
    

