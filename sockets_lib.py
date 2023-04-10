import socket
from socket import *

from cryptography_lib import *


@dataclass
class ConnectedEntity:
    socket: socket
    cert: Cert
    address: str
    port: int
    authenticated: bool
    byte_buffer: bytearray

    def __init__(self, entity_socket: socket, entity_address, entity_port, cert: Cert = None):
        if cert is not None:
            self.cert = cert
        self.socket = entity_socket
        self.address = entity_address
        self.port = entity_port
        self.byte_buffer = bytearray()

    # Encodes data (in byte array format) to base64 format and delimits using '|' character. Sends to socket
    def send_bytes(self, data_bytes: bytes | bytearray):
        # Byte array buffer
        data_out = bytearray()
        # Encode data to Base64 and add to buffer
        data_out.extend(base64.b64encode(data_bytes))
        # Add delimiter character to signify end of stream message
        data_out.extend(b'|')
        # Send data out
        self.socket.send(data_out)

    # Used to receive all data from socket; combines all data received until '|' delimiter in base64 encoding
    def receive_bytes(self):
        # Always running in thread
        while b'|' not in self.byte_buffer:
            # Wait for data to be received from socket connection and add onto buffer
            data = self.socket.recv(1024)
            self.byte_buffer.extend(data)

        data_out, self.byte_buffer = self.byte_buffer.split(b'|', maxsplit=1)
        return bytes(base64.b64decode(data_out))

    def send_cert(self, cert: Cert):
        self.send_bytes(
            base64.b64encode(
                cert.to_bytes()
            )
        )

    def receive_cert(self):
        cert_bytes = self.receive_bytes()
        cert = Cert()
        cert.from_bytes(
            base64.b64decode(cert_bytes)
        )
        return cert

    def send_challenge_response(self, signer_private_key: rsa.RSAPrivateKey, challenge: int):
        challenge_cipher = rsa_encrypt(str(challenge).encode("utf-8"), self.cert.pubkey)
        message = bytearray()
        # Challenge
        message.extend(
            base64.b64encode(
                challenge_cipher
            )
        )
        # Message delimiter
        message.extend(b',')
        # Signed Challenge
        message.extend(
            base64.b64encode(
                signer_private_key.sign(
                    challenge_cipher,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            )
        )
        self.send_bytes(message)

    def receive_challenge_response(self, receiver_private_key: rsa.RSAPrivateKey):
        data = self.receive_bytes()
        auth_data = data.split(b',')

        challenge_response_cipher = base64.b64decode(auth_data[0])

        challenge_response = rsa_decrypt(
            challenge_response_cipher,
            receiver_private_key
        )

        signature = base64.b64decode(auth_data[1])

        return challenge_response, challenge_response_cipher, signature

    def authenticate_server(self, client_cert: Cert, challenge: int, client_private_key: rsa.RSAPrivateKey):
        # Send certificate to server
        self.send_cert(client_cert)
        # Send challenge to server
        self.send_challenge_response(client_private_key, challenge)
        (response_bytes, response_cipher, signature) = self.receive_challenge_response(client_private_key)
        # Decode challenge response back to integer type
        challenge_response = int(response_bytes.decode("utf-8"))
        # Check that the response matches to challenge
        if challenge_response != challenge:
            raise Exception("Challenge response incorrect from server!")
        # print("Challenge response passed. :)")
        if not self.cert.verify_signature(response_cipher, signature):
            raise Exception("Server signature verification failed!")
        # print("Signature verification passed. :)")

        (response_bytes, response_cipher, signature) = self.receive_challenge_response(client_private_key)
        # Decode challenge response back to integer type
        challenge_response = int(response_bytes.decode("utf-8"))
        # Send challenge response
        self.send_challenge_response(client_private_key, challenge_response)

    def authenticate_client(self, challenge: int, server_private_key: rsa.RSAPrivateKey):
        # Receive certificate from client
        self.cert = self.receive_cert()
        # Receive challenge from client
        (challenge_bytes, challenge_cipher, signature) = self.receive_challenge_response(server_private_key)
        # Decode actual challenge
        challenge_response = int(challenge_bytes.decode("utf-8"))
        # Verify the sender's signature
        if not self.cert.verify_signature(challenge_cipher, signature):
            raise Exception("Client signature verification failed!")
        # print("Signature verification passed. :)")

        # Send challenge response
        self.send_challenge_response(server_private_key, challenge_response)
        # Send challenge
        self.send_challenge_response(server_private_key, challenge)

        # New challenge response
        (challenge_bytes, challenge_cipher, signature) = self.receive_challenge_response(server_private_key)
        challenge_response = int(challenge_bytes.decode("utf-8"))
        if not self.cert.verify_signature(challenge_cipher, signature):
            raise Exception("Client signature verification failed!")

        # Check that the response matches to challenge
        if challenge_response != challenge:
            raise Exception("Challenge response incorrect from client!")
        # print("Challenge response passed. :)")
