from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
from cryptography.exceptions import * 
import base64

# ---------------------------------------------------------------
# Function definitons for encryption
# ---------------------------------------------------------------

# Encrypt using RSA key
def RSA_encrypt(message, key): 
    return key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt using RSA key
def RSA_decrypt(message, key): 
    return key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Encrypt using AES key
def AES_encrypt(message, key): 
    padded_message = pad(message, AES.block_size) 
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.encrypt(padded_message) 

# Decrypt text using an AES key
def AES_decrypt(message, key): 
    cipher = AES.new(key, AES.MODE_ECB) 
    padded_message = cipher.decrypt(message) 
    return unpad(padded_message, AES.block_size)

# Used to get the hash of a message
def hash(message): 
    # return SHA256.new(data=message).hexdigest()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode('utf-8'))
    return digest.finalize()

# Used to load in public RSA PEM key from file
def load_pubkey(key_path):
    return serialization.load_pem_public_key(
        open(key_path, 'rb').read(),
    )

# Used to load in private RSA PEM key from file
def load_privkey(key_path):
    return serialization.load_pem_private_key(
        open(key_path, 'rb').read(),
        password=None
    )

# ---------------------------------------------------------------
# Certificate class, storage, verification, signing and others
# ---------------------------------------------------------------

# Dataclass for easier use of custom certificatess
@dataclass
class Cert:
    # Stores certificate public key, ID as a string, certificate signature from "certificate authority (pubcert privkey)"
    pubkey: rsa.RSAPublicKey
    userid: str
    signature: bytearray

    def __init__(self, userid=None, pubkey=None, pubcert_privkey=None):
        if userid is not None:
            self.sign_cert(pubcert_privkey)

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
            base64.b64encode(self.signature)
        )
        return out_bytes

    # Populates cert instance using a datastream that includes cert
    def from_bytes(self, bytes: bytearray):
        cert_bytes = bytes.split(b',')
        self.signature = base64.b64decode(cert_bytes[2])
        self.userid = base64.b64decode(cert_bytes[0]).decode("utf-8")
        self.pubkey = serialization.load_pem_public_key(base64.b64decode(cert_bytes[1]))

    # Authenticates this certificates signature usng a sent message and the encrypted counterpart
    def authenticate_signature(self, message: bytearray, signature: bytearray):
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
    def authenticate_cert(self, pubcert_key: rsa.RSAPublicKey):
        prehash = bytearray()
        prehash.extend(self.userid.encode("utf-8"))
        prehash.extend(self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        try:
            pubcert_key.verify(
                self.signature,
                prehash,
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
    def sign_cert(self, pubcert_privkey: rsa.RSAPrivateKey):
        prehash = bytearray()
        prehash.extend(self.userid.encode("utf-8"))
        prehash.extend(self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self.signature = pubcert_privkey.sign(
            prehash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )