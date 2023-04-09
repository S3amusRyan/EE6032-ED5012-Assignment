from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cyptography_lib import *
import argparse

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Cert Generator',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-k', '--issuerkey', type=str, required=True)
parser.add_argument('-i', '--pubkey', type=str, required=True)
parser.add_argument('-u', '--userid', type=str, required=True)
parser.add_argument('-o', '--out', type=str)

args = parser.parse_args()

subject_pubkey = load_pubkey(args.pubkey)

ca_privkey = load_privkey(args.issuerkey)

cert = Cert()
cert.userid = args.userid
cert.pubkey = subject_pubkey
cert.sign_cert(ca_privkey)

open(args.out, 'wb').write(cert.to_bytes())