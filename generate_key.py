# Cryptography implementation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
    prog='EE6032 RSA Key Generator',
    description='EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-o', '--out', type=str, nargs='+')

args = parser.parse_args()

for outfile in args.out:
    key_prv = rsa.generate_private_key(65537, 2048)
    pem_prv = key_prv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption())
    open(outfile, 'wb').write(pem_prv)
    print("Written private key to '", outfile, "'")

    key_pub = key_prv.public_key()
    pem_pub = key_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)
    open(outfile + ".pub", 'wb').write(pem_pub)
    print("Written public key to '", outfile, ".pub'")
