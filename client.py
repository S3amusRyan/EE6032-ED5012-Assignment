import socket
import argparse

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Client',
                    epilog = 'Put in IPv4 address to connect to')
# Server address, default is localhost
parser.add_argument('-a', '--address', default='localhost', type=str)
# Server port, default is 25565
parser.add_argument('-p', '--port', default=80, type=int)

# Main
def main():

    # Attempt to connect to server socket
    try:

        # Parse address and port from arguments
        args = parser.parse_args()
        host_address = socket.gethostbyname(args.address)
        host_port = args.port
        print("Attempting to connect to server client at ", host_address, ":", host_port)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host_address, host_port))
        print("Socket successfully created.")

    except socket.error as err:

        print("Connection to server socket failed!")
        print(err)

    except socket.gaierror:

        print("Error resolving the host")

if __name__ == "__main__":
    main()