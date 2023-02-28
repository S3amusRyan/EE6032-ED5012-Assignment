from socket import *
from threading import *
from tkinter import *
import argparse
import sys

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Server')

# Server address, default is localhost
parser.add_argument('-u', '--user', choices=['A', 'B', 'C'], required=True, type=str.upper)

args = parser.parse_args()

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

hostIp = "127.0.0.1"
portNumber = 7500

clientSocket.connect((hostIp, portNumber))

window = Tk()
window.title("Connected To: "+ hostIp+ ":"+str(portNumber))

txtMessages = Text(window, width=50)
txtMessages.grid(row=0, column=0, padx=10, pady=10)

txtYourMessage = Entry(window, width=50)
txtYourMessage.insert(0,"")
txtYourMessage.grid(row=1, column=0, padx=10, pady=10)

def sendMessage(event=None):
    clientMessage = txtYourMessage.get()
    txtMessages.insert(END, "\n" + "You: "+ clientMessage)
    clientSocket.send(clientMessage.encode("utf-8"))
    txtYourMessage.delete(0, END)

btnSendMessage = Button(window, text="Send", width=20, command=sendMessage)
btnSendMessage.grid(row=2, column=0, padx=10, pady=10)

txtYourMessage.bind('<Return>', sendMessage)

def recvMessage():
    while True:
        serverMessage = clientSocket.recv(1024).decode("utf-8")
        print(serverMessage)
        txtMessages.insert(END, "\n"+serverMessage)

recvThread = Thread(target=recvMessage)
recvThread.daemon = True
recvThread.start()

window.mainloop()

if args.user not in ['A', 'B', 'C']:
    print("Invalid user specified. Exiting...")
    sys.exit(1)
