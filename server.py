# ---------------------------------------------------------------
# EE6032: Communication & Security Protocols
# Protocol Design Project
#
# Adam Dooley		19252056
# Danila Fedotov	19267371
# Ronan Randles	    19242441
# Seamus Ryan		19254555
#
# Script name: server.py
#
# Description: Script to run which acts as the server as
# described in the design doccument. 
# ---------------------------------------------------------------
import argparse
import os
import random
import threading

from sockets_lib import *

server_cert = Cert().from_bytes(open("certs/S.cert", 'rb').read())
server_private_key = load_private_key("keys/S")
ca_public_key = load_public_key("keys/PUBCERT.pub")

# ---------------------------------------------------------------
# Script input arguments section
# ---------------------------------------------------------------

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
    prog='EE6032 Client',
    description='EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-a', '--address', default='127.0.0.1', type=str)
parser.add_argument('-p', '--port', default=7500, type=int)

args = parser.parse_args()

# Create a set to hold all client sockets
clients = {
    "A": None,
    "B": None,
    "C": None
}

# Create a socket object for the server
host_socket = socket(AF_INET, SOCK_STREAM)
host_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

# Set IP address and port number for server socket
host_socket.bind((args.address, args.port))

# Listen for incoming connections
host_socket.listen()
print("Waiting for connections...")

# Start a loop to accept incoming connections and create threads for each one
while None in clients.values():
    # Accept incoming connection and get client socket and address
    client_socket, client_address = host_socket.accept()
    print("Connection established with: ", client_address[0] + ":" + str(client_address[1]))

    new_client = ConnectedEntity(client_socket, client_address[0], client_address[1])
    try:
        new_client.authenticate_client(int.from_bytes(os.urandom(32), 'little'), server_private_key, ca_public_key)
    except Exception as e:
        print(e)
        new_client.socket.shutdown(SHUT_RDWR)
        new_client.socket.close()
        continue
    print("Client", new_client.cert.userid, "has been authenticated :)")

    if clients[new_client.cert.userid] is None:
        clients[new_client.cert.userid] = new_client

print("All clients added")

for i in range(2):
    for j in clients:
        data = clients[j].receive_bytes()
        for k in clients:
            clients[k].send_bytes(data)


def client_thread(client: ConnectedEntity, all_clients):
    while True:
        message = client.receive_bytes()
        for out_client in all_clients:
            out_client.send_bytes(message)


for client in clients:
    threading.Thread(target=client_thread, args=(clients[client], clients.values())).start()

while True:
    continue
