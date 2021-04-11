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

    #  Client Registration; reception and parsing of message content (4)
    #  (Application Server -> Client)
    #  Expected message contents:
    #  [Application Server Public-Key||Certificate||Timestamp4]
    receivedData4 = applicationServer.recv(4096)
    dataDecoded4 = receivedData4.decode("utf-8")
    receivedTimestamp4 = dataDecoded4[-10:]
    receivedApplicationServerPublicKey = dataDecoded4[0:461]
    print('\nReceived plaintext: "{}"'.format(dataDecoded4))
    #  print('\nExtracted timestamp4: "{}"'.format(receivedTimestamp4))
    #  print('\nExtracted application server public-key: "{}"'.format(receivedApplicationServerPublicKey))
    certificate = dataDecoded4.replace(receivedTimestamp4, '').replace(receivedApplicationServerPublicKey, '')
    #  print('\nExtracted certificate: "{}"'.format(certificate))

    #  Verification of received application server public-key and certificate

    #  Client Registration; second construction and sending of message content (5)
    #  (Client -> Application Server)
    #  Constructed message contents:
    #  [Temporary Key2||Client ID||Client IP Address||Client Port||Timestamp5]
    tempKey2 = get_random_bytes(8)
    print('\nSecond temporary-key generated: "{}"'.format(tempKey2.decode("utf-8")))
    timestamp5 = time.time().__trunc__()
    message5 = tempKey2.decode("utf-8").__str__() + client1_id + HOST + PORT.__str__() + timestamp5.__str__()
    encodedMessage5 = message5.encode("utf-8")

    #  public-key retrieval -> centralized certificate authority
    applicationServer_publicKey = RSA.import_key(
        open("applicationServer_publicKey.pem").read())

    RSA_cipher5 = PKCS1_OAEP.new(applicationServer_publicKey)
    encryptedSessionKey5 = RSA_cipher5.encrypt(tempKey2)
    cipher_aes5 = AES.new(tempKey2, AES.MODE_EAX)
    ciphertext5, tag5 = cipher_aes5.encrypt_and_digest(encodedMessage5)
    file_out = open("encrypted_data.bin", "wb")
    [file_out.write(x) for x in (encryptedSessionKey5, cipher_aes5.nonce, tag5, ciphertext5)]
    file_out.close()
    time.sleep(5)

    #  Client Registration; second reception and parsing of message content (6)
    #  (Application Server -> Client)
    #  Expected message contents:
    #  [Session Key||Session Lifetime||Client ID||Timestamp6]
    cipher6 = DES.new(tempKey2, DES.MODE_OFB)
    file_in = open("encrypted_data.bin", "rb")
    data6 = file_in.read()
    data6Decrypted = cipher6.decrypt(data6)
    data6Decoded = data6Decrypted.decode("utf-8")
    print(data6Decoded)










