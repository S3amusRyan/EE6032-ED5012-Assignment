import argparse
import random
import sys
from threading import *
from tkinter import *
import time
from sockets_lib import *

# ---------------------------------------------------------------
# Script input arguments section
# ---------------------------------------------------------------

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
    prog='EE6032 Client',
    description='EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-u', '--user', choices=['A', 'B', 'C'], required=True, type=str.upper, default='A')
parser.add_argument('-a', '--address', default='127.0.0.1', type=str)
parser.add_argument('-p', '--port', default=7500, type=int)

args = parser.parse_args()

# ---------------------------------------------------------------
# Key and cert initial management section
# ---------------------------------------------------------------

# Get client cert, public and private keys
client_cert = Cert()
client_cert.from_bytes(open("certs/" + args.user + ".cert", 'rb').read())
client_public_key = client_cert.pubkey
client_private_key = load_private_key("keys/" + args.user)

# Get server cert and public keys
server_cert = Cert()
server_cert.from_bytes(open("certs/S.cert", 'rb').read())
server_pubkey = server_cert.pubkey

# ---------------------------------------------------------------
# Socket connections section
# ---------------------------------------------------------------

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server_socket.connect((args.address, args.port))
print("Connected to: ", args.address, ":", args.port)

server = ConnectedEntity(server_socket, args.address, args.port, server_cert)
try:
    server.authenticate_server(client_cert, random.randint(1, 1023), client_private_key)
except Exception as e:
    print(e)
    print("test")
    server.socket.close()
    sys.exit()

# ---------------------------------------------------------------
# Mutual Key Agreement Section
# ---------------------------------------------------------------
for i in {'A','B','C'}:
    if client_cert.userid != i:
        dest_cert = Cert()
        dest_cert.from_bytes(open("certs/" + i + ".cert", 'rb').read())
        server.key_send(client_cert.userid, i, server.rand_nums, dest_cert.pubkey, client_private_key)
        print("Client Sent to ", i)

for i in range(6):
    print("waiting")
    server.key_recieve(client_private_key, client_cert.userid)
    print("Client Recieved")

print("Rand NUMS: ", server.rand_nums)
# Establish mutually agreed key
Kabc = sha256_hash(str(server.rand_nums))
print("Mutual Key: " + str(Kabc))
# ---------------------------------------------------------------
# Tk GUI Section
# ---------------------------------------------------------------

# Initialises the chat window
window = Tk()
window.title("Name: Client " + args.user + "         Connected To: " + args.address + ":" + str(args.port))

# Make the client box scalable
window.rowconfigure(0, weight=1)
window.columnconfigure(0, weight=1)

txt_messages = Text(window, width=50)
txt_messages.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

txt_your_message = Entry(window, width=50)
txt_your_message.insert(0, "")
txt_your_message.grid(row=1, column=0, padx=10, pady=10, sticky="ew")


# when send button is pressed: pull message from chat box, clear chat box, 
def send_message(event=None):
    client_message = txt_your_message.get()  # pull message in chat box
    txt_messages.insert(END, "\n" + "Client " + args.user + ": " + client_message)
    # client_socket.send(client_message)
    # send_data(client_socket, client_message.encode("utf-8"))
    txt_your_message.delete(0, END)  # clear message box


btn_send_message = Button(window, text="Send", width=20, command=send_message)  # Creating send button
btn_send_message.grid(row=2, column=0, padx=10, pady=10, sticky="e")

txt_your_message.bind('<Return>', send_message)  # Send message if return key is pressed


def recv_message():  # When message is received
    while True:
        server_message = server_socket.recv(1024).decode("utf-8")
        # print(server_message)                                                    #Print message in console
        txt_messages.insert(END, "\n" + server_message)  #


recv_thread = Thread(target=recv_message)
recv_thread.daemon = True
recv_thread.start()

window.mainloop()

# ---------------------------------------------------------------
# Main method section
# ---------------------------------------------------------------
