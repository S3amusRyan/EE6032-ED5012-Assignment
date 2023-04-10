import argparse
import random
from threading import *

from sockets_lib import *

server_cert = Cert().from_bytes(open("certs/S.cert", 'rb').read())
server_private_key = load_private_key("keys/S")
ca_public_key = load_public_key("keys/PUBCERT.pub")


def client_thread(client: ConnectedEntity):
    # Start an infinite loop to receive and send messages to client
    while True:
        continue
    # if clients_authenticated:
    # Receive message from client
    # data = client.receive_bytes()
    # if not data:
    #     clients.remove(client)
    #     print(client_address[0] + ":" + str(client_address[1]) + " disconnected")
    #     break

    # message = data.decode("utf-8")

    # Print message and client address to server console
    # print(client_address[0] + ":" + str(client_address[1]) + " says: " + message)
    # for client in clients:
    #     if client is not client_socket:
    #         client.send((client_address[0] + ":" + str(client_address[1]) + " says: " + message).encode("utf-8"))

    client.socket.close()


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

# Start an infinite loop to accept incoming connections and create threads for each one
while True:
    # Accept incoming connection and get client socket and address
    client_socket, client_address = host_socket.accept()
    print("Connection established with: ", client_address[0] + ":" + str(client_address[1]))

    new_client = ConnectedEntity(client_socket, client_address[0], client_address[1])
    try:
        new_client.authenticate_client(random.randint(0, 1023), server_private_key, ca_public_key)
    except Exception as e:
        print(e)
        new_client.socket.shutdown(SHUT_RDWR)
        new_client.socket.close()
        continue
    print("Client", new_client.cert.userid, "has been authenticated :)")

    if clients[new_client.cert.userid] is not None:
        clients[new_client.cert.userid] = new_client

    # TODO: Only start threads once all three are connected and authenticated
    # TODO: Remove from client array if disconnected before key exchange

    # TODO: MIGHT NOT NEED MULTITHREADING, SINGLE THREAD CAN DO FINE

    # TODO: AES Key negotiation
    # TODO: AES Message send and receive
    thread = Thread(target=client_thread, args=(new_client,))
    thread.start()
