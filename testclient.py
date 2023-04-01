from socket import *
from threading import *
from tkinter import *
import argparse
import sys
import hashlib 
import rsa 
import os 
import sys 
import json 
from Crypto.Cipher import AES as aes
from Crypto.Util.Padding import pad, unpad
import random

# Encrypt using RSA key
def rsa_encrypt(message, pubkey): 
    return rsa.encrypt(message.encode(), pubkey)

# Decrypt using RSA key
def rsa_decrypt(ciphertext, privkey): 
    return rsa.decrypt(ciphertext, privkey).decode() 

# Encrypt using AES key
def aes_encrypt(message, key): 
    padded_message = pad(message.encode(), AES.block_size) 
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.encrypt(padded_message) 

# Decrypt text using an aes key
def aes_decrypt(ciphertext, key): 
    cipher = AES.new(key, AES.MODE_ECB) 
    padded_message = cipher.decrypt(ciphertext) 
    return unpad(padded_message, AES.block_size).decode() 

# Used to ge the hash of a message
def sha256(message): 
    return hashlib.sha256(message.encode()).hexdigest() 

# Used to load in public RSA PEM key from file
def load_pubkey(key_path):
    with open(key_path, 'rb') as p:
        return rsa.PublicKey.load_pkcs1(p.read())

# Used to load in private RSA PEM key from file
def load_privkey(key_path):
    with open(key_path, 'rb') as p:
        return rsa.PrivateKey.load_pkcs1(p.read())

# Method used to perform handshake with server
def handshake_send():
    NR = random.randint(0,1023)
    message = client_cert + rsa_encrypt(NR, pubkeys["S"]) + rsa_encrypt(sha256(rsa_encrypt(NR, pubkeys["S"])), privkeys[args.user])
    clientSocket.send(message)

# ---------------------------------------------------------------
# Loading keys into program section
# ---------------------------------------------------------------

# Array for public keys of A, B and C
pubkeys = {
    "A": load_pubkey("keys/pubkey_A.pem"),
    "B": load_pubkey("keys/pubkey_B.pem"),
    "C": load_pubkey("keys/pubkey_C.pem"),
    "PUBCERT": load_pubkey("keys/pubkey_PUBCERT.pem"),
    "S": load_pubkey("keys/pubkey_S.pem")
}

# Array for private keys of A, B and C
privkeys = {
    "A": load_privkey("keys/privkey_A.pem"),
    "B": load_privkey("keys/privkey_B.pem"),
    "C": load_privkey("keys/privkey_C.pem"),
    "PUBCERT": load_privkey("keys/privkey_PUBCERT.pem"),
    "S": load_privkey("keys/privkey_S.pem")
}

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

# Get client cert using user ID, In a real life scenario this is not done during runtime
client_cert = args.user + rsa.PublicKey. pubkeys[args.user].exportKey() + rsa_encrypt(sha256(args.user + pubkeys[args.user]), privkeys["PUBCERT"])


pubkey = pubkeys[args.user]
privkey = privkeys[args.user]
    
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

clientSocket.connect((args.address, args.port))

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
    clientSocket.send(clientMessage)
    txtYourMessage.delete(0, END)                                               #clear message box

btnSendMessage = Button(window, text="Send", width=20, command=sendMessage)     #Creating send button
btnSendMessage.grid(row=2, column=0, padx=10, pady=10, sticky="e")

txtYourMessage.bind('<Return>', sendMessage)                                    #Send message if return key is pressed
    
    
def recvMessage():                                                              #When mesage is received 
    while True:
        serverMessage = clientSocket.recv(1024).decode("utf-8")
        print(serverMessage)                                                    #Print message in console
        txtMessages.insert(END, "\n"+serverMessage)                             #


recvThread = Thread(target=recvMessage)
recvThread.daemon = True
recvThread.start()

window.mainloop()

# ---------------------------------------------------------------
# Main method section
# ---------------------------------------------------------------

if args.user not in ['A', 'B', 'C']:
    print("Invalid user specified. Exiting...")
    sys.exit(1)