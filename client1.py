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
import string
import random

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

    #  Client Registration; construction and sending of message content (3)
    #  (Client -> Application Server)
    #  Constructed message contents:
    #  [Application Server ID||Timestamp3]
    timestamp3 = time.time().__trunc__()
    message3 = applicationServer_id + timestamp3.__str__()
    encodedMessage3 = message3.encode("utf-8")
    applicationServer.sendall(encodedMessage3)

    #  Client Registration; reception and parsing of message content (4)
    #  (Application Server -> Client)
    #  Expected message contents:
    #  [Application Server Public-Key||Certificate||Timestamp4]
    receivedData4 = applicationServer.recv(4096)
    receivedDataDecoded4 = receivedData4.decode("utf-8")
    receivedTimestamp4 = receivedDataDecoded4[-10:]
    upperBoundApplicationServerPublicKey = receivedDataDecoded4.rindex("END PUBLIC KEY-----") + 17
    lowerBoundApplicationServerPublicKey = receivedDataDecoded4.find("-----BEGIN PUBLIC KEY")
    receivedApplicationServerPublicKey = \
        receivedDataDecoded4[lowerBoundApplicationServerPublicKey:upperBoundApplicationServerPublicKey]
    print('\nReceived plaintext from application server: "{}"'.format(receivedDataDecoded4))
    certificate = receivedDataDecoded4.replace(receivedTimestamp4, '').replace(receivedApplicationServerPublicKey, '')

    #  Verification of received application server public-key and certificate

    #  Client Registration; second construction and sending of message content (5)
    #  (Client -> Application Server)
    #  Constructed message contents:
    #  [Temporary Key2||Client ID||Client IP Address||Client Port||Timestamp5]
    letters = string.ascii_lowercase
    client_tk = (''.join(random.choice(letters) for i in range(8)))
    print('\nSecond temporary-key generated: "{}"'.format(client_tk))
    timestamp5 = time.time().__trunc__()
    message5 = client_tk + client1_id + HOST + PORT.__str__() + timestamp5.__str__()
    encodedMessage5 = message5.encode("utf-8")

    #  Application server public-key importation
    applicationServer_publicKey = RSA.import_key(receivedApplicationServerPublicKey)

    RSA_cipher5 = PKCS1_OAEP.new(applicationServer_publicKey)
    encryptedMessageEncoded5 = RSA_cipher5.encrypt(encodedMessage5)
    applicationServer.sendall(encryptedMessageEncoded5)
    print('\nSent ciphertext to application server: "{}"'.format(encryptedMessageEncoded5))

    #  Client Registration; second reception and parsing of message content (6)
    #  (Application Server -> Client)
    #  Expected message contents:
    #  [Session Key||Session Lifetime||Client ID||Timestamp6]
    receivedData6 = applicationServer.recv(4096)
    des_cipher6 = DES.new(client_tk.encode("utf-8"), DES.MODE_OFB)
    receivedDataDecrypted6 = des_cipher6.decrypt(receivedData6)
    print('\nReceived ciphertext from application server: "{}"'.format(receivedData6))
    receivedDataDecryptedDecoded6 = receivedDataDecrypted6.decode("utf-8")
    upperBoundSessionKeyExtract6 = receivedDataDecryptedDecoded6.find('86400')
    extractedSessionKey6 = receivedDataDecryptedDecoded6[0:upperBoundSessionKeyExtract6]
    print('\nReceived session key from application server: "{}"'.format(extractedSessionKey6))










