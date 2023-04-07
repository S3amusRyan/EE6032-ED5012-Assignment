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
from Crypto.Util.Padding import pad, unpad
import random
import base64

# ---------------------------------------------------------------
# Function definitons for encryption
# ---------------------------------------------------------------

# Encrypt using RSA key
def RSA_encrypt(message, key): 
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message.encode('utf-8'))

# Decrypt using RSA key
def RSA_decrypt(message, key): 
    cipher = RSA.new(key)
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

def client_auth():
    print("Authenticating...")

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

# Define function to handle each client connection in a separate thread
def clientThread(client_socket, client_address):
    # Start an infinite loop to receive and send messages to client
    while True:
        # if clients_authenticated:
        # Receive message from client
        message = client_socket.recv(1024).decode('utf-8')
        # Print message and client address to server console
        print(client_address[0] + ":" + str(client_address[1]) +" says: "+ message)
        for client in clients:
            if client is not client_socket:
                client.send((client_address[0] + ":" + str(client_address[1]) +" says: "+ message).encode("utf-8"))

        # If message is empty, remove client from set and close connection
        if not message:
            clients.remove(client_socket)
            print(client_address[0] + ":" + str(client_address[1]) +" disconnected")
            break

    client_socket.close()

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
    thread = Thread(target=clientThread, args=(client_socket, client_address))
    thread.start()