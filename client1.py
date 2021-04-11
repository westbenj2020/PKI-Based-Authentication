import socket
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import time
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'  # IP address for server socket
PORT = 65432  # port for server socket
networkAddress = HOST + PORT.__str__()
BLOCK_SIZE = 32
client1_id = 'ID-Client1'
applicationServer_id = 'ID-Server'
centralizedCertificateAuthority_id = 'ID-CA'
req = 'memo'
data = 'take cis3319 class this morning'
sessionLifetime = 86400

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as applicationServer:
    applicationServer.connect((HOST, PORT))
    print('\nClient is running...')
    print('\nConnected to application server using IP address "{}" - port "{}"...'.format(HOST, PORT))

    #  Client Registration; construction and sending of message content
    #  (Client -> Application Server)
    #  Constructed message contents:
    #  [Application Server ID||Timestamp3]
    timestamp = time.time().__trunc__()
    message = applicationServer_id + timestamp.__str__()
    encodedMessage = message.encode("utf-8")
    applicationServer.sendall(encodedMessage)

    #  Client Registration; reception and parsing of message content
    #  (Application Server -> Client)
    #  Expected message contents:
    #  [Application Server Public-Key||Certificate||Timestamp4]
    receivedData = applicationServer.recv(1024)



