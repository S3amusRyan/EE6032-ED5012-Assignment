import argparse

from cryptography_lib import *

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
    prog='EE6032 Cert Generator',
    description='EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-k', '--issuerkey', type=str, required=True)
parser.add_argument('-i', '--pubkey', type=str, required=True)
parser.add_argument('-u', '--userid', type=str, required=True)
parser.add_argument('-o', '--out', type=str)

args = parser.parse_args()

subject_pubkey = load_public_key(args.pubkey)

ca_private_key = load_private_key(args.issuerkey)

cert = Cert()
cert.userid = args.userid
cert.pubkey = subject_pubkey
cert.sign_cert(ca_private_key)

open(args.out, 'wb').write(cert.to_bytes())
