from socket import *
from threading import *

clients_authenticated = False

privkey =   "-----BEGIN RSA PRIVATE KEY-----\
            MIICXAIBAAKBgQDVDZ9pEih3RqYepeCzoFoykyc7V2drZICc66eLc/RXeR3QU0ik\
            aANCJCU0vkjQKseEVTxzbF7ZpqJn9g3BA6lC8a9+y9L/vGBz07hmuROjD4uQjJfO\
            W9s0jPmBehHXKi/kCEAtQZLCO34zAAbYwwmFLa1hjuTrpeVMSS+03fOw1wIDAQAB\
            AoGANbiKoobGl1TEHGQ9JW3gcHI0aT0fwa+E0oyFIZ+qU8ghYV8uqO3lLG9KxmLY\
            n0y6JD8N0BjaTc07lDUxwKJ4sgejPg9UEOtvA6uqtjMSOqgS/Wf/hfpwAE7eAkvi\
            R7wQACYjBbeJexdNuLsmIYjp6l2+3GHsKAWYcE8hBUxMreECQQD2+Oj/LxAinPVZ\
            3tjp8xwP4owsbleEWcnaOKzhugI1Y5Sm3/ckS6Oo860QPe9ZGSDfNT+MZ75+kiPv\
            /zwQJHqRAkEA3NdO6oWZcZRKDpxJUuCNCSWIIe7YFW0UhSQNV7/VWo0xlnaRcdQN\
            kN7zykgWfnFq7T1u0iGPOEP+I+iJk5OY5wJAO9ugPRkfBASewqVsVWeCyabS6oHj\
            3EQW1DkgTaVTm7UC9l8Z+0YJ6I0GyQT52dJpUTAKsvECDpNE+ooV+KOewQJBAI1E\
            wfutuMl6JaGRAiqc8DtQofOq+NlD7ON6e3qNgWqqdXUdpc6d6ouow2S7loAOB2t5\
            Z+HNi/NfMzw/LXqU6TMCQHLPvY843dkUtEy6XX+4cc3QdenKFAOc35U78VBn7ad1\
            ygT3LWz2qZF3zOnMRz9x7xlYnhEffsgUMgSHSD7upUE=\
            -----END RSA PRIVATE KEY-----"

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
portNumber = 7501
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