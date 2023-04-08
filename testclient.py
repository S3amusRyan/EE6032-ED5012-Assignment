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
    cipher = PKCS1_OAEP.new(key)
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

def load_cert_file(cert_path):
    cert_file = open(cert_path, "rb").read()
    cert_name, pubkey_b64, keyhash_b64 = cert_file.split(b',')
    pubkey = RSA.import_key(base64.b64decode(pubkey_b64))
    keyhash = base64.b64decode(keyhash_b64)
    cert = {"name": cert_name, "pubkey": pubkey, "cert": cert_file}
    return cert

# ---------------------------------------------------------------
# Function definitons for sockets and handshakes
# ---------------------------------------------------------------

# Used to receive all data from socket; combines all data received until '|' delimiter in base64 encoding
def receive_data(socket):
    # Byte array buffer 
    data_buffer = bytearray()
    # Always running in thread
    while b'|' not in data_buffer:
        # Wait for data to be received from socket connection and add onto buffer
        try:
            data = socket.recv(1024)
            if not data:
                return 0
            data_buffer.extend(data)
        except OSError as e:
            print(e)
            return 0
    if not data_buffer:
        return 0
    data_out = data_buffer.split(b'|')[0]
    return base64.b64decode(data_out)

# Encodes data (in byte array format) to base64 format and delimits using '|' character. Sends to socket
def send_data(socket, data):
    # Byte array buffer
    data_out = bytearray()
    # Encode data to Base64 and add to buffer
    data_out.extend(base64.b64encode(data))
    # Add delimiter character to signify end of stream message
    data_out.extend(b'|')
    # Sned data out
    socket.send(data_out)


# Method used to perform handshake with server
def client_auth(socket, certificate, random_int, server_pubkey, client_privkey):

    message = bytearray()
    message.extend(base64.b64encode(certificate))
    message.extend(b',')
    message.extend(base64.b64encode(RSA_encrypt(str(random_int), server_pubkey)))
    message.extend(b',')
    message.extend(base64.b64encode(RSA_encrypt( hash(RSA_encrypt(str(random_int), server_pubkey)), client_privkey )))
    message.extend(b'|')

    print("Attempting to authenticate...")

    send_data(socket, message)
    send_data(socket, b'just a test')

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
client_cert = load_cert_file("certs/cert_" + args.user)
client_pubkey = client_cert["pubkey"]
client_privkey = load_privkey("keys/privkey_" + args.user + ".pem")

# Get server cert and public keys
server_cert = load_cert_file("certs/cert_S")
server_pubkey = server_cert["pubkey"]

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
    
client_auth(client_socket, client_cert["cert"], random.randint(1, 1023), server_pubkey, client_privkey)

def recvMessage():                                                              #When mesage is received 
    while True:
        serverMessage = client_socket.recv(1024).decode("utf-8")
        print(serverMessage)                                                    #Print message in console
        txtMessages.insert(END, "\n"+serverMessage)                             #

recvThread = Thread(target=recvMessage)
recvThread.daemon = True
recvThread.start()

window.mainloop()

# ---------------------------------------------------------------
# Main method section
# ---------------------------------------------------------------

