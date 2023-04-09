from socket import *
from threading import *
from tkinter import *
import argparse
import os 
import sys 
from cyptography_lib import *
from sockets_lib import *
import random
import base64

server_cert = Cert().from_bytes(open("certs/S.cert", 'rb').read())
server_privkey = load_privkey("keys/S")
pubcert_key = load_pubkey("keys/PUBCERT.pub")

# ---------------------------------------------------------------
# Function definitons for sockets and handshakes
# ---------------------------------------------------------------

def client_auth(socket, server_privkey: rsa.RSAPrivateKey, server_cert: Cert, pubcert_key: rsa.RSAPublicKey):
    data = receive_data(socket)
    auth_data = data.split(b',')

    client_cert = Cert()
    client_cert.from_bytes(
        base64.b64decode(auth_data[0])
    )

    random_num_str = RSA_decrypt(
        base64.b64decode(auth_data[1]),
        server_privkey
    )

    print("Authenticating certificate of", client_cert.userid)
    if not client_cert.authenticate_cert(pubcert_key):
        print("Client certificate authenticity not verified! Closing socket.")
        socket.close()
        return
    print("Client certificate authenticated :)")

    print("Authenticating signature of", client_cert.userid)
    sig_auth = client_cert.authenticate_signature(
        base64.b64decode(auth_data[1]),
        base64.b64decode(auth_data[2]))
    if not sig_auth:
        print("Client signature authentication failed. Closing socket.") 
        socket.close()
        return
    print("Client signature authenticated :)")

# Define function to handle each client connection in a separate thread
def client_thread(client_socket, client_address):

    client_auth(client_socket, server_privkey, server_cert, pubcert_key)

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