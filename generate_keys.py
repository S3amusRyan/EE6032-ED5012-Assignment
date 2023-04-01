from Crypto.PublicKey import RSA as rsa

for instance in {"A", "B", "C", "S", "PUBCERT"}:

    # Generate keypair
    key = rsa.generate(2048)

    # Write Private key
    f = open('keys/privkey_'+instance+'.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    # Write Public key
    f = open('keys/pubkey_'+instance+'.pem', 'wb')
    f.write(key.public_key().export_key('PEM'))
    f.close()