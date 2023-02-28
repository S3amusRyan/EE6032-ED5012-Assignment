import hashlib 
import rsa 
import os 
import sys 
import json 
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad

def RSA_Encrypt(message, pubkey): 
    return rsa.encrypt(message.encode(), pubkey)

def RSA_Decrypt(ciphertext, privkey): 
    return rsa.decrypt(ciphertext, privkey).decode() 

def AES_Encrypt(message, key): 
    padded_message = pad(message.encode(), AES.block_size) 
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.encrypt(padded_message) 

def AES_Decrypt(ciphertext, key): 
    cipher = AES.new(key, AES.MODE_ECB) 
    padded_message = cipher.decrypt(ciphertext) 
    return unpad(padded_message, AES.block_size).decode() 

def SHA256(message): 
    return hashlib.sha256(message.encode()).hexdigest() 

# Entity A 
def establish_session_key(B_cert, C_cert, S_pubkey): 
    # Generate random session key Kabc 
    Kabc = os.urandom(16) 
    # Encrypt session key with B and C's public keys 
    Kabc_encrypted_B = RSA_Encrypt(Kabc, B_cert['pubkey']) 
    Kabc_encrypted_C = RSA_Encrypt(Kabc, C_cert['pubkey']) 
    # Compute hash of session key 
    hash_Kabc = SHA256(Kabc) 
    # Encrypt hash of session key with AES and session key 
    hash_Kabc_encrypted = AES_Encrypt(hash_Kabc, Kabc) 
    # Package encrypted session key and encrypted hash of session key 
    package = { 
    'Kabc_encrypted_B': Kabc_encrypted_B, 
    'Kabc_encrypted_C': Kabc_encrypted_C, 
    'hash_Kabc_encrypted': hash_Kabc_encrypted 
    } 
    # Send package to B and C through S 
    S_package_encrypted = RSA_Encrypt(json.dumps(package), S_pubkey) 
    send_to_S(S_package_encrypted) 

# Entity B and C 
def receive_session_key(): 
    # Receive package from S 
    S_package_encrypted = receive_from_S() 
    package = json.loads(RSA_Decrypt(S_package_encrypted, privkey)) 
    # Decrypt session key and hash of session key 
    Kabc = RSA_Decrypt(package['Kabc_encrypted_B'], privkey) 
    hash_Kabc_encrypted = package['hash_Kabc_encrypted'] 
    hash_Kabc = AES_Decrypt(hash_Kabc_encrypted, Kabc) 
    # Verify hash of session key 
    if hash_Kabc != SHA256(Kabc): 
        print("Hash of session key does not match, aborting") 
        sys.exit(0) 
        
    return Kabc 
    # 
