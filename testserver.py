from socket import *
from threading import *

# Create a set to hold all client sockets
clients = set()

# Define function to handle each client connection in a separate thread
def clientThread(clientSocket, clientAddress):
    # Start an infinite loop to receive and send messages to client
    while True:
        # if clients_authenticated:
        # Receive message from client
        message = clientSocket.recv(1024)
        # Print message and client address to server console
        print(clientAddress[0] + ":" + str(clientAddress[1]) +" says: "+ message)
        for client in clients:
            if client is not clientSocket:
                client.send((clientAddress[0] + ":" + str(clientAddress[1]) +" says: "+ message).encode("utf-8"))

        # If message is empty, remove client from set and close connection
        if not message:
            clients.remove(clientSocket)
            print(clientAddress[0] + ":" + str(clientAddress[1]) +" disconnected")
            break

    clientSocket.close()

# Create a socket object for the server
hostSocket = socket(AF_INET, SOCK_STREAM)
hostSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR,1)

# Set IP address and port number for server socket
hostIp = "127.0.0.1"
portNumber = 7500
hostSocket.bind((hostIp, portNumber))

# Listen for incoming connections
hostSocket.listen()
print ("Waiting for connection...")

# Start an infinite loop to accept incoming connections and create threads for each one
while True:
    # Accept incoming connection and get client socket and address
    clientSocket, clientAddress = hostSocket.accept()
    clients.add(clientSocket)
    print ("Connection established with: ", clientAddress[0] + ":" + str(clientAddress[1]))
    thread = Thread(target=clientThread, args=(clientSocket, clientAddress, ))
    thread.start()