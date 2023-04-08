from socket import *
from threading import *
from tkinter import *
import argparse
import os 
import sys 
import json 
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss as PSS
from Crypto.Util.Padding import pad, unpad
import random
import base64

# ---------------------------------------------------------------
# NEED TO REPLACE PYCRYPTODOME PACKAGES WITH CRYPTOGRAPHY
# PACKAGES
#
# PyCrypto is not maintained. PyCryptodome has limitations making
# it impossible to implement low-level authentication. (required
# for the project)
# 
# Cryptography up to date and can use it for everything
# --------------------------------------------------------------- 

# ---------------------------------------------------------------
# Function definitons for encryption
# ---------------------------------------------------------------

# Encrypt using RSA key
def RSA_encrypt(message, key): 
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message.encode('utf-8'))

# Decrypt using RSA key
def RSA_decrypt(message, key): 
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message).decode('utf-8')

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

# Used to ge the hash of a message
def hash(message): 
    return SHA256.new(data=message).hexdigest()

# Used to load in public RSA PEM key from file
def load_pubkey(key_path):
    with open(key_path, 'r') as p:
        return RSA.import_key(p.read())

# Used to load in private RSA PEM key from file
def load_privkey(key_path):
    with open(key_path, 'r') as p:
        return RSA.import_key(p.read())

server_privkey = load_privkey("keys/privkey_S.pem")
pubcert_key = load_pubkey("keys/pubkey_PUBCERT.pem")

# ---------------------------------------------------------------
# Function definitons for sockets and handshakes
# ---------------------------------------------------------------

# Used to receive all data from socket; combines all data received until '|' delimiter in base64 encoding
def receive_data(socket):
    # Byte array buffer 
    data_buffer = bytearray()
    # Always running in thread
    while b'|' not in data_buffer:
        # Wait for data to be received from socket connection and add onto buffer
        try:
            data = socket.recv(1024)
            if not data:
                return 0
            data_buffer.extend(data)
        except OSError as e:
            print(e)
            return 0
    if not data_buffer:
        return 0
    data_out = data_buffer.split(b'|')[0]
    return base64.b64decode(data_out)

# Encodes data (in byte array format) to base64 format and delimits using '|' character. Sends to socket
def send_data(socket, data):
    # Byte array buffer
    data_out = bytearray()
    # Encode data to Base64 and add to buffer
    data_out.extend(base64.b64encode(data))
    # Add delimiter character to signify end of stream message
    data_out.extend(b'|')
    # Sned data out
    socket.send(data_out)

def client_auth(socket, server_privkey, pubcert_key):
    auth_data = receive_data(socket).split(b',')

    certificate = base64.b64decode(auth_data[0])
    cert_contents = certificate.split(b',')
    cert_id = cert_contents[0]
    cert_pubkey = RSA.import_key(base64.b64decode(cert_contents[1]))
    cert_keyhash = RSA_decrypt( base64.b64decode(cert_contents[2]), pubcert_key)

    print("Authenticating client ", cert_id.decode("utf-8"))

    cert_auth_keyhash = bytearray()
    cert_auth_keyhash.extend(cert_id)
    cert_auth_keyhash.extend(cert_pubkey)
    cert_auth_keyhash = hash(cert_auth_keyhash)

    if cert_keyhash is not cert_auth_keyhash:
        print("Certificate authentication failed for ", cert_id.decode("utf-8"))
        socket.close()
    print("Certificate authenticated :)")

# Define function to handle each client connection in a separate thread
def client_thread(client_socket, client_address):

    client_auth(client_socket, server_privkey, pubcert_key)

    # Start an infinite loop to receive and send messages to client
    while True:
        # if clients_authenticated:
        # Receive message from client
        data = receive_data(client_socket)
        if not data:
            clients.remove(client_socket)
            print(client_address[0] + ":" + str(client_address[1]) +" disconnected")
            break

        message = data.decode("utf-8")

        # Print message and client address to server console
        print(client_address[0] + ":" + str(client_address[1]) +" says: "+ message)
        for client in clients:
            if client is not client_socket:
                client.send((client_address[0] + ":" + str(client_address[1]) +" says: "+ message).encode("utf-8"))

    client_socket.close()

# ---------------------------------------------------------------
# Script input arguments section
# ---------------------------------------------------------------

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-a', '--address', default='127.0.0.1', type=str)
parser.add_argument('-p', '--port', default=7500, type=int)

args = parser.parse_args()

# Create a set to hold all client sockets
clients = set()



# Create a socket object for the server
hostSocket = socket(AF_INET, SOCK_STREAM)
hostSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)

# Set IP address and port number for server socket
hostSocket.bind((args.address, args.port))

# Listen for incoming connections
hostSocket.listen()
print ("Waiting for connections...")

# Start an infinite loop to accept incoming connections and create threads for each one
while True:
    # Accept incoming connection and get client socket and address
    client_socket, client_address = hostSocket.accept()
    clients.add(client_socket)
    print ("Connection established with: ", client_address[0] + ":" + str(client_address[1]))
    thread = Thread(target=client_thread, args=(client_socket, client_address))
    thread.start()