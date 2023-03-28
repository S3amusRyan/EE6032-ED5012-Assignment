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
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
import random

def RSA_Encrypt(message, pubkey): 
    return rsa.encrypt(message.encode(), pubkey)

def RSA_Decrypt(ciphertext, privkey): 
    return rsa.decrypt(ciphertext, privkey).decode() 

def AES_Encrypt(message, key): 
    padded_message = pad(message.encode(), AES.block_size) 
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.encrypt(padded_message) 

def AES_Decrypt(ciphertext, key): 
    cipher = AES.new(key, AES.MODE_ECB) 
    padded_message = cipher.decrypt(ciphertext) 
    return unpad(padded_message, AES.block_size).decode() 

def SHA256(message): 
    return hashlib.sha256(message.encode()).hexdigest() 

# Array for public keys of A, B and C
pubkeys = {}
privkeys = {}

def load_keys(keys_path):
    for instance in {"A", "B", "C", "S", "PUBCERT"}:
        with open(keys_path + 'pubkey_' + instance + '.pem', "rb") as p:
            pubkeys[instance] = rsa.PublicKey.load_pkcs1(p.read())
        with open(keys_path + 'privkey_' + instance + '.pem', "rb") as p:
            privkeys[instance] = rsa.PrivateKey.load_pkcs1(p.read())

load_keys("keys/")

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-u', '--user', choices=['A', 'B', 'C'], required=True, type=str.upper)
parser.add_argument('-a', '--address', default='127.0.0.1', type=str)
parser.add_argument('-p', '--port', default=7501, type=int)

args = parser.parse_args()

# Get client cert using user ID, In a real life scenario this is not done during runtime
client_cert = args.user + pubkeys[args.user] + RSA_Encrypt(SHA256(args.user + pubkeys[args.user]), privkeys["PUBCERT"])

pubkey = pubkeys[args.user]
privkey = privkeys[args.user]
    
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

clientSocket.connect((args.address, args.port))

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

if args.user not in ['A', 'B', 'C']:
    print("Invalid user specified. Exiting...")
    sys.exit(1)

def handshake_send():
    NR = random.randint(0,1023)
    message = client_cert + RSA_Encrypt(NR, pubkeys["S"]) + RSA_Encrypt(SHA256(RSA_Encrypt(NR, pubkeys["S"])), privkeys[args.user])
    clientSocket.send(message)
    client_setup1 = True

client_authenticated = False
client_handhsake_intioated = False
client_ = False