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
import random
import string

#  network configuration information

HOST = '127.0.0.1'  # IP address for server socket
PORT = 65432  # port for server socket
networkAddress = HOST + PORT.__str__()
BLOCK_SIZE = 32
client1_id = 'ID-Client1'
applicationServer_id = 'ID-Server'
centralizedCertificateAuthority_id = 'ID-CA'
sessionLifetime = 86400
data = 'take cis3319 class this morning'

#  temporary DES key retrieval -> application server
letters = string.ascii_lowercase
applicationServer_tk = (''.join(random.choice(letters) for i in range(8)))
print('\nTemporary DES key retrieved: "{}"'.format(applicationServer_tk))

#  public-key retrieval -> centralized certificate authority
centralizedCertificateAuthority_publicKey = RSA.import_key(open(
    "CCA_centralizedCertificateAuthority_publicKey.pem").read())

#  connection logic
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as applicationServer:
    applicationServer.bind((HOST, PORT))
    applicationServer.listen()
    print('\nApplication server is running...')
    print('\nAccepted new connection from IP address "{}" - port "{}"...'.format(HOST, PORT))
    centralizedCertificateAuthority, address = applicationServer.accept()
    with centralizedCertificateAuthority:

        #  Application server registration; construction and sending of data (1)
        #  (Application Server -> Centralized Certificate Authority)
        #  Constructed message contents:
        #  [Application Server Temporary Key1(8 chars)||ID of Application Server(9 chars)||Timestamp1(10 digits)
        timestamp1 = time.time().__trunc__()
        nonEncryptedMessage1 = applicationServer_tk.__str__() + applicationServer_id + timestamp1.__str__()
        nonEncryptedMessageEncoded1 = nonEncryptedMessage1.encode("utf-8")
        RSA_cipher1 = PKCS1_OAEP.new(centralizedCertificateAuthority_publicKey)
        encryptedMessageEncoded1 = RSA_cipher1.encrypt(nonEncryptedMessageEncoded1)
        print('\nSent ciphertext: "{}"'.format(encryptedMessageEncoded1))
        centralizedCertificateAuthority.sendall(encryptedMessageEncoded1)

        #  Application server registration; reception and parsing of message contents (2)
        #  (Centralized Certificate Authority -> Application Server)
        #  Expected message contents:
        #  [Application Server Public-Key||Application Server Private-Key +\
        #  ||Certificate||Application Server ID||Timestamp2]
        cipher2 = DES.new(applicationServer_tk.encode('utf-8'), DES.MODE_ECB)
        receivedData2 = centralizedCertificateAuthority.recv(4096)
        receivedDataDecrypted2 = cipher2.decrypt(receivedData2)  # stores decoded byte data as string
        unpad(receivedDataDecrypted2, BLOCK_SIZE)
        receivedDataDecryptedDecoded2 = receivedDataDecrypted2.decode("utf-8").strip()
        print('\nTEST >>> "{}"'.format(receivedDataDecrypted2))
        print('\nReceived ciphertext: "{}"'.format(receivedData2))
        receivedTimestamp2 = receivedDataDecryptedDecoded2[-10:]
        receivedApplicationServerID = receivedDataDecryptedDecoded2[-19:-10]
        upperBoundApplicationServerPublicKey = receivedDataDecryptedDecoded2.rindex("END PUBLIC KEY-----") + 19
        lowerBoundApplicationServerPublicKey = receivedDataDecryptedDecoded2.find("-----BEGIN PUBLIC KEY")
        receivedApplicationServerPublicKey =\
            receivedDataDecryptedDecoded2[lowerBoundApplicationServerPublicKey:upperBoundApplicationServerPublicKey]
        upperBoundApplicationServerPrivateKey = receivedDataDecryptedDecoded2.rindex("END RSA PRIVATE KEY-----") + 24
        lowerBoundApplicationServerPrivateKey = receivedDataDecryptedDecoded2.find("-----BEGIN RSA PRIVATE KEY")
        receivedApplicationServerPrivateKey =\
            receivedDataDecryptedDecoded2[lowerBoundApplicationServerPrivateKey:upperBoundApplicationServerPrivateKey]
        print('\nReceived public-key for independent usage: "{}"'.format(receivedApplicationServerPublicKey))
        print('\nReceived private-key for independent usage: "{}"'.format(receivedApplicationServerPrivateKey))
        certificateWithExcess = receivedDataDecryptedDecoded2.replace(receivedTimestamp2, '')\
            .replace(receivedApplicationServerPublicKey, '').\
            replace(receivedApplicationServerPrivateKey, '').replace(receivedApplicationServerID, '')
        certificate = certificateWithExcess[6:]
        print('\nReceived certificate = "{}"'.format(certificate))

        #

        #  Connecting with client for phase two of protocol
        client, clientAddress = applicationServer.accept()
        with client:

            #  Client Registration; reception of message contents (3)
            #  (Client -> Application Server)
            #  Expected message contents:
            #  [Application Server ID||Timestamp3]
            receivedData3 = client.recv(4096)
            print('\nReceived plaintext from client: "{}"'.format(receivedData3.decode("utf-8")))

            #  Client Registration; construction and sending of message contents (4)
            #  (Application Server -> Client)
            #  Constructed message contents:
            #  [Application Server Public-Key||Certificate||Timestamp4]
            timestamp4 = time.time().__trunc__()
            message4 = receivedApplicationServerPublicKey + certificate + timestamp4.__str__()
            encodedMessage4 = message4.encode("utf-8")
            client.sendall(encodedMessage4)

            #  Client Registration; second reception - and parsing - of message contents (5)
            #  (Client -> Application Server)
            #  Expected message contents:
            #  [Temporary Key2||Client ID||Client IP Address||Client Port||Timestamp5]
            receivedData5 = client.recv(4096)
            print('\nReceived ciphertext from client: "{}"'.format(receivedData5))

            #  Application server public-key importation
            applicationServer_privateKey = RSA.import_key(receivedApplicationServerPrivateKey)

            RSA_cipher5 = PKCS1_OAEP.new(applicationServer_privateKey)
            decryptedMessageEncoded5 = RSA_cipher5.decrypt(receivedData5)
            decryptedMessageDecoded5 = decryptedMessageEncoded5.decode("utf-8")
            upperBoundTempKeyExtract5 = decryptedMessageDecoded5.find('ID-')
            extractedTempKey5 = decryptedMessageDecoded5[0:upperBoundTempKeyExtract5]
            print('\nReceived temporary DES key from client: "{}"'.format(extractedTempKey5))

            #  Client Registration; construction and sending of message contents (6)
            #  (Application Server -> Client)
            #  Constructed message contents:
            #  [Session Key||Session Lifetime||Client ID||Timestamp6]
            letters = string.ascii_lowercase
            session_key = (''.join(random.choice(letters) for k in range(8)))
            print('\nGenerated session key: "{}"'.format(session_key))
            timestamp6 = time.time().__trunc__()
            message6 = session_key.__str__() + sessionLifetime.__str__() + client1_id + timestamp6.__str__()
            message6Encoded = message6.encode("utf-8")
            cipher6 = DES.new(extractedTempKey5.encode("utf-8"), DES.MODE_OFB)
            message6EncodedEncrypted = cipher6.encrypt(message6Encoded)
            client.sendall(message6EncodedEncrypted)
            print('\nSent ciphertext to client: "{}"'.format(message6EncodedEncrypted))

            #  Service Request; reception and parsing of message content (7)
            #  (Client -> Application Server)
            #  Expected message contents:
            #  [req||Timestamp7]
            receivedData7 = client.recv(4096)
            print('\nReceived ciphertext from client: "{}"'.format(receivedData7))
            cipher7 = DES.new(session_key.encode("utf-8"), DES.MODE_OFB)
            receivedData7Decrypted = cipher7.decrypt(receivedData7)
            receivedData7DecryptedDecoded = receivedData7Decrypted.decode("utf-8")
            extractedTimestamp7 = receivedData7DecryptedDecoded[-10:]
            req = receivedData7DecryptedDecoded.replace(extractedTimestamp7, '')
            print('\nReceived message from client: "{}"'.format(req))

            #  Service Request; construction and transmission of message content (8)
            #  (Application Server -> Client)
            #  Constructed message contents:
            #  [data||Timestamp8]
            timestamp8 = time.time().__trunc__()
            message8 = data + timestamp8.__str__()
            cipher8 = DES.new(session_key.encode("utf-8"), DES.MODE_OFB)
            message8Encoded = message8.encode("utf-8")
            message8EncodedEncrypted = cipher8.encrypt(message8Encoded)
            client.sendall(message8EncodedEncrypted)
            print('\nSent ciphertext to client: "{}"'.format(message8EncodedEncrypted))













