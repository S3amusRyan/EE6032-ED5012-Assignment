import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dataclasses import dataclass
from cryptography.exceptions import *
import base64


# ---------------------------------------------------------------
# Function definitions for encryption
# ---------------------------------------------------------------

# Encrypt using RSA key
def rsa_encrypt(message, key):
    return key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# Decrypt using RSA key
def rsa_decrypt(message, key):
    return key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# Encrypt using AES key
def aes_encrypt(message: bytes | bytearray, key: bytes | bytearray):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), )


# Decrypt text using an AES key
def aes_decrypt(message, key):



# Used to get the hash of a message
def sha256_hash(message):
    # return SHA256.new(data=message).hexdigest()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8'))
    return digest.finalize()


# Used to load in public RSA PEM key from file
def load_public_key(key_path):
    return serialization.load_pem_public_key(
        open(key_path, 'rb').read(),
    )


# Used to load in private RSA PEM key from file
def load_private_key(key_path):
    return serialization.load_pem_private_key(
        open(key_path, 'rb').read(),
        password=None
    )


# ---------------------------------------------------------------
# Certificate class, storage, verification, signing and others
# ---------------------------------------------------------------

# Dataclass for easier use of custom certificates
@dataclass
class Cert:
    # Stores certificate public key, ID as a string, certificate signature from "certificate authority
    # private key"
    pubkey: rsa.RSAPublicKey
    userid: str
    public_cert_signature: bytes

    def __init__(self, userid=None, pubkey=None, ca_private_key=None):
        if userid is not None and pubkey is not None:
            self.sign_cert(ca_private_key)

    # returns whole certificate as a bytes array encoded in base64 for storage and transfer
    # Delimited using comma ','
    def to_bytes(self):
        out_bytes = bytearray()
        out_bytes.extend(
            base64.b64encode(self.userid.encode("utf-8"))
        )
        out_bytes.extend(b',')
        out_bytes.extend(
            base64.b64encode(self.pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        )
        out_bytes.extend(b',')
        out_bytes.extend(
            base64.b64encode(self.public_cert_signature)
        )
        return out_bytes

    # Populates cert instance using a datastream that includes cert
    def from_bytes(self, input_bytes: bytes):
        cert_bytes = input_bytes.split(b',')
        self.public_cert_signature = base64.b64decode(cert_bytes[2])
        self.userid = base64.b64decode(cert_bytes[0]).decode("utf-8")
        self.pubkey = serialization.load_pem_public_key(base64.b64decode(cert_bytes[1]))

    # Authenticates this certificates signature using a received message and the encrypted counterpart
    def verify_signature(self, message: bytes, signature: bytes):
        try:
            self.pubkey.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    # Authenticates the certificate if correctly signed using the signer's public key
    def authenticate_cert(self, ca_public_key: rsa.RSAPublicKey):
        message = bytearray()
        message.extend(self.userid.encode("utf-8"))
        message.extend(self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        try:
            ca_public_key.verify(
                self.public_cert_signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    # Sign the certificate using issuer's private key. Not used in runtime.
    def sign_cert(self, ca_private_key: rsa.RSAPrivateKey):
        message = bytearray()
        message.extend(self.userid.encode("utf-8"))
        message.extend(self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self.public_cert_signature = ca_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
