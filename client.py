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

# ---------------------------------------------------------------
# Function definitons for sockets and handshakes
# ---------------------------------------------------------------

# Method used to perform handshake with server
def client_auth(socket, client_cert: Cert, server_pubkey: rsa.RSAPublicKey, random_int: int, client_privkey: rsa.RSAPrivateKey):

    # First part of client authentication:
    # Sending client certificate, random number as a challenge as well as signature to confirm authenticity
    # First part of message: client certificate
    random_int_content = RSA_encrypt(str(random_int).encode("utf-8"), server_pubkey)
    message = bytearray()
    message.extend(
        base64.b64encode(
            client_cert.to_bytes()
        )
    )
    # Message delimiter
    message.extend(b',')
    # Second part of message: Random number encrypted
    message.extend(
        base64.b64encode(
            random_int_content
        )
    )
    # Message delimiter
    message.extend(b',')
    # Final part of message: Random number signed using private key
    message.extend(
        base64.b64encode(
            client_privkey.sign(
                random_int_content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        )
    )
    print("Attempting to authenticate...")
    send_data(socket, message)

    # Second part of client authentication:
    # Waiting for challenge response from server

# ---------------------------------------------------------------
# Script input arguments section
# ---------------------------------------------------------------

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-u', '--user', choices=['A', 'B', 'C'], required=True, type=str.upper)
parser.add_argument('-a', '--address', default='127.0.0.1', type=str)
parser.add_argument('-p', '--port', default=7500, type=int)

args = parser.parse_args()

# ---------------------------------------------------------------
# Key and cert inital management section
# ---------------------------------------------------------------

# Get client cert, public and private keys
client_cert = Cert()
client_cert.from_bytes( open("certs/" + args.user + ".cert", 'rb').read() )
client_pubkey = client_cert.pubkey
client_privkey = load_privkey("keys/" + args.user)

# Get server cert and public keys
server_cert = Cert()
server_cert.from_bytes( open("certs/S.cert", 'rb').read() )
server_pubkey = server_cert.pubkey

# ---------------------------------------------------------------
# Socket connections section
# ---------------------------------------------------------------

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
client_socket.connect((args.address, args.port))

print("Connected to: ", args.address, ":", args.port)

# ---------------------------------------------------------------
# Tk GUI Section
# ---------------------------------------------------------------

#Initialises the chat window
window = Tk()   
window.title("Name: Client " + args.user + "         Connected To: " + args.address + ":" + str(args.port))

# Make the client box scalable
window.rowconfigure(0, weight=1)
window.columnconfigure(0, weight=1)

txtMessages = Text(window, width=50)
txtMessages.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

txtYourMessage = Entry(window, width=50)
txtYourMessage.insert(0,"")
txtYourMessage.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

#when send button is pressed: pull message from chat box, clear chat box, 
def sendMessage(event=None):                                                    
    clientMessage = txtYourMessage.get()                                        #pull message in chat box
    txtMessages.insert(END, "\n" + "Client " + args.user + ": "+ clientMessage) 
    # client_socket.send(clientMessage)
    send_data(client_socket, clientMessage.encode("utf-8"))
    txtYourMessage.delete(0, END)                                               #clear message box

btnSendMessage = Button(window, text="Send", width=20, command=sendMessage)     #Creating send button
btnSendMessage.grid(row=2, column=0, padx=10, pady=10, sticky="e")

txtYourMessage.bind('<Return>', sendMessage)                                    #Send message if return key is pressed
    
client_auth(client_socket, client_cert, server_pubkey, random.randint(1, 1023), client_privkey)

def recvMessage():                                                              #When mesage is received 
    while True:
        serverMessage = client_socket.recv(1024).decode("utf-8")
        # print(serverMessage)                                                    #Print message in console
        txtMessages.insert(END, "\n"+serverMessage)                             #

recvThread = Thread(target=recvMessage)
recvThread.daemon = True
recvThread.start()

window.mainloop()

# ---------------------------------------------------------------
# Main method section
# ---------------------------------------------------------------

