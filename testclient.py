from socket import *
from threading import *
from tkinter import *
import argparse
import sys



# Array for public keys of A, B and C
pubkeys = {"A":
            "-----BEGIN PUBLIC KEY-----\
            MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFCOyDz0W6rst54LZC8vxwKU4oYg\
            D2jbXM+kHyJQkJHFxQkW5U57xGFq+bm8jO7CgAmpYyUKhKm+eKmzgHb5YnuTyoPW\
            Ua7H1KNMfnlAwKykqh/zV+rY4mrrWmqhnelc3W0o5ZPEN/15aGtXIZFLUpEUinXi\
            El4LSYn8jWngneNjAgMBAAE=\
            -----END PUBLIC KEY-----",
            "B":
            "-----BEGIN PUBLIC KEY-----\
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD5Z+53sgAizDJZ/Yedn7HYPh9e\
            GIpZUO43i50damEF6w2j5HTFl1wUnWn5Mm4VmM3rXu12pZJyMzKQkaJUz0VS/wEd\
            dTGT0O55F34sNB93ET1iWlwwk/oMjYe89dg7QOBCflFSGlAO9sWFq+QQfxfryqbu\
            KBHUJmWKcMw+LHYBgwIDAQAB\
            -----END PUBLIC KEY-----",
            "C":
            "-----BEGIN PUBLIC KEY-----\
            MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFrNRQm1aXkCS9wlZQH0Z1s+GOeq\
            vjnHDHYpAoaipgWTvzbHxZtG1AfBsvHu7Qh///OJIpfrQkHUcqO6mSWzJA8ODtgT\
            1IRN2AUnW3VLBCjLP2pP1M+QVUnC35mgJF/4dgbpyZmRfQ6xctcPFCwtcak8POOZ\
            0aBzBbbuDOCnwdANAgMBAAE=\
            -----END PUBLIC KEY-----"}

privkeys = {"A":
            "-----BEGIN RSA PRIVATE KEY-----\
            MIICWgIBAAKBgFCOyDz0W6rst54LZC8vxwKU4oYgD2jbXM+kHyJQkJHFxQkW5U57\
            xGFq+bm8jO7CgAmpYyUKhKm+eKmzgHb5YnuTyoPWUa7H1KNMfnlAwKykqh/zV+rY\
            4mrrWmqhnelc3W0o5ZPEN/15aGtXIZFLUpEUinXiEl4LSYn8jWngneNjAgMBAAEC\
            gYA+qNDXmLo0mSu5ouKqUV9agrQv34Ac74Ohfuc4qbHJsSsxhr2V7m8x1yOndSGq\
            FV/CJB8aELRf0+fHF/g0koYm+SosFVUUmBe22G/3eM+73w5Qp6mrg1EtG7ERJo9E\
            RRcMEK54zTKjKpfG7eHH7dKx9GJVFyt8m3Q+N74bE368AQJBAJqhn12JA58r0Rid\
            sEsMvkUKJXNXH6iSB/3FhnfsUG0VyVBpiOLIv8Ho0d3tjfe9AvGP9h1cdcSDt4C5\
            P8A0u5MCQQCFXg8PhHsK3hl5RIBwSHpFijRnSIgcPiT+JKfw9qU1Y0ZwNzbGN+CF\
            3dgehdyt7SO3NKBDV3mticBDmeVB3jrxAkBOgr9Co32GRJ4OzImlIVw9+4/WRycY\
            1MRf8fl7TC3tpQEo5dyNoPXTw51C/Al3/qzO75Q7hiV5WJNENUqMEXonAkAiKEnx\
            LnwY93NMxMekeluejdwIC+KYYS42TQsaQwFjIA79VJbZw5vkjUH550zy2saH+JmH\
            RdMrKBmu9q5p5VHxAkBG2sWCj+cFxvtbud7YfS5h4zNA/GKeugcnUmJNRJwQl3eI\
            +TFD0u1FcLoOmPxiUEhG5YBTyZwSNAuowqT8+xHN\
            -----END RSA PRIVATE KEY-----",
            "B":
            "-----BEGIN RSA PRIVATE KEY-----\
            MIICXQIBAAKBgQD5Z+53sgAizDJZ/Yedn7HYPh9eGIpZUO43i50damEF6w2j5HTF\
            l1wUnWn5Mm4VmM3rXu12pZJyMzKQkaJUz0VS/wEddTGT0O55F34sNB93ET1iWlww\
            k/oMjYe89dg7QOBCflFSGlAO9sWFq+QQfxfryqbuKBHUJmWKcMw+LHYBgwIDAQAB\
            AoGASBPdOwJaP7Q7qP44PzlzsEbj0dHNydo1vh+/HE0uFQPFQWQ4yxHfLqX/hmEo\
            p10txaP9hJh9JjvdlSJBg7kTE0NH76TPB2z2ALAVowNGale6rSbb8iWjlfWEDLIi\
            xrEOboADmPpDVbhsIGiT2hBG/A1JgGViLFYrVuAZBAkBnKECQQD/bBn8o63BVrOm\
            ofAYr7B/Mg9kSWv/XFHG88/lKPrtm4npKCjbl1r9bP9+lBCZQSQvctamGgYqoqOn\
            KtOzNKOHAkEA+fhYqwProTnWVcvPo7dj+urfdOVks3bO0bAsIUoxFMDqWAnYA3Ym\
            DjCqqWOky7YQzqce0lQgDNmz+UOAnPhpJQJBAOH4RVVZiVNO3UlCYyOz6zXcl/ll\
            a4JTrpWRBg/7HWQxAuWffeYoFXu3fqIBZF3xX44KzxPMWkBF+vrdzMTygOkCQGek\
            jfcSYA9wMKtQHx6tejneSppoRnGWsDgHCLUg0urc9g1cv4Dn6u11Rj2HgBuquJtG\
            daQVl1hcp5+RWnE7GjUCQQDVJXR3twIY1GuMupKjBssTMWSJRQvOPCr8k9Wojif0\
            TqUiBAlmPbPKJz22/NXxFwsjqgzY+SX1fNpY7P5ZIkn2\
                    -----END RSA PRIVATE KEY-----",
            "C":
            "-----BEGIN RSA PRIVATE KEY-----\
            MIICWgIBAAKBgFrNRQm1aXkCS9wlZQH0Z1s+GOeqvjnHDHYpAoaipgWTvzbHxZtG\
            1AfBsvHu7Qh///OJIpfrQkHUcqO6mSWzJA8ODtgT1IRN2AUnW3VLBCjLP2pP1M+Q\
            VUnC35mgJF/4dgbpyZmRfQ6xctcPFCwtcak8POOZ0aBzBbbuDOCnwdANAgMBAAEC\
            gYASZ7Equp7abGC8CshikQuyLvAVZUKRq4sXGFDuwWEtmDkV/YBMbRrlR5nh+DAL\
            nQZgcteUO5d+iHWEQnpwbdNNC4xrxqrA4DD27Xvrr3RRjIR9r2L1/ADo62qqviT3\
            VjbUGwTeAXGJN7fv17+By1KvRJfmVysJTkvlPOuihZI/8QJBAK47ED3pI+zD4Pof\
            KGCILJpUrK1xuVR+Oujh7Amkj5BL8wOrbvNXWUx0gCIsxeM6s9dwAK06S+TqlMBD\
            7XkKQc8CQQCFaqY+ea9B+lWx/5yiVR1mEQJ5ScbHYrf4XtdGfYzRpvz4D1irkadX\
            QAZM4zUOFDhlDDGlajnvXUgWy/eNmBNjAkBQ/oAEZ9cdf8mcPNPGXEdvzyEe2Bkx\
            oCS+khfqO6fJiqUD9bP0R4zpr9bJDEtJ4MYtxpFp9gnF9w8DehBxDkWdAkAL61ZE\
            2Jw2ucW0LFDzE8WXm8drzJKMt54V+2siKg9Nn6yUANL8KPwZSGgHsHjJ9DaBmJBK\
            5e2dG+lX2AsaxE5fAkBl3sWOV9WfaHgi8OXWgOWFKRosRQk2Dq3/ptjJ4SGbgpyx\
            Vlfxe/EofOSZT/jzvPU2mcB+9E6SKT8UaSwK1Lgf\
            -----END RSA PRIVATE KEY-----"}

# Argument Parser and defining arguments
parser = argparse.ArgumentParser(
                    prog = 'EE6032 Client',
                    description = 'EE6032 Project Client')

# Server address, default is localhost
parser.add_argument('-u', '--user', choices=['A', 'B', 'C'], required=True, type=str.upper)
parser.add_argument('-a', '--address', default='localhost', type=str)
parser.add_argument('-p', '--port', default=7500, type=int)

args = parser.parse_args()
    
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

def sendMessage(event=None):                                                    #when send button is pressed
    clientMessage = txtYourMessage.get()                                        #pull message in chat box
    txtMessages.insert(END, "\n" + "Client " + args.user + ": "+ clientMessage) 
    clientSocket.send(clientMessage.encode("utf-8"))
    txtYourMessage.delete(0, END)                                               #clear message box

btnSendMessage = Button(window, text="Send", width=20, command=sendMessage)     #Initilises
btnSendMessage.grid(row=2, column=0, padx=10, pady=10, sticky="e")

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

def main():
    print(args.user)

if __name__ == "__main__":
    main()

