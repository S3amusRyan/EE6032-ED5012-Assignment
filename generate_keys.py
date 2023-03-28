import rsa 

def generateKeys(name):
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open('keys/pubkey_' + name +  '.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privkey_' + name + '.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

keys = {"A", "B", "C", "S", "PUBCERT"}

for name in keys:
    generateKeys(name)
