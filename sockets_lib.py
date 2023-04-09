from socket import *
import base64

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
def send_data(socket, data: bytearray()):
    # Byte array buffer
    data_out = bytearray()
    # Encode data to Base64 and add to buffer
    data_out.extend(base64.b64encode(data))
    # Add delimiter character to signify end of stream message
    data_out.extend(b'|')
    # Sned data out
    socket.send(data_out)