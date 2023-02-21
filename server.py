import socket
import argparse

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Server')

# Server address, default is localhost
parser.add_argument('-a', '--address', default='localhost', type=str)
# Server port, default is 25565
parser.add_argument('-p', '--port', default=25565, type=int)

def main():
    print("Init Server...")

    try:
        print("Creating server socket...")
        
        # Parse address and port from arguments
        args = parser.parse_args()
        host_address = socket.gethostbyname(args.address)
        host_port = args.port

        print("Attempting to create server socket at ", host_address, ":", host_port)
        # create an INET, STREAMing socket
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to a public host, and a well-known port
        serversocket.bind((host_address, host_port))
        # become a server socket
        serversocket.listen(5)

    except:
        print("Failed to create server socket!")

    while True:
        (clientsocket, address) = serversocket.accept()
        print("Connected client from ", address)


if __name__ == "__main__":
    main()
