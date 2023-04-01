import argparse
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import base64

# Encrypt using RSA key
def RSA_encrypt(message, key): 
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message.encode('utf-8'))

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Custom Certificate Creator',
                    description = 'Creates certificates for project using public key inputs')

# Server address, default is localhost
parser.add_argument('-i', '--keyin', required=True, type=str)
parser.add_argument('-p', '--certprivkey', required=True, type=str)
parser.add_argument('-u', '--user', required=True, type=str)
parser.add_argument('-o', '--certout', required=True, type=str)

args = parser.parse_args()

# Used to load in public RSA PEM key from file
pubkey = RSA.import_key(open(args.keyin, 'r').read())
cert_privkey = RSA.import_key(open(args.certprivkey, 'r').read())

# Generate certificate
client_cert = bytearray()
client_cert.extend((args.user + "\n").encode())
client_cert.extend(base64.b64encode(pubkey.export_key('PEM')))
client_cert.extend(b"\n")
client_cert.extend(base64.b64encode(RSA_encrypt(SHA256.new(data=client_cert).hexdigest(), cert_privkey)))

# Write the cert out to file
out_file = open(args.certout, 'wb')
# out_file.write(base64.b64encode((client_cert)))
out_file.write(client_cert)
out_file.close()