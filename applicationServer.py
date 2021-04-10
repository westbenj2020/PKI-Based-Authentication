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

#  network configuration information

HOST = '127.0.0.1'  # IP address for server socket
PORT = 65432  # port for server socket
networkAddress = HOST + PORT.__str__()
BLOCK_SIZE = 256
client1_id = 'ID-Client1'
applicationServer_id = 'ID-Server'
centralizedCertificateAuthority_id = 'ID-CA'
sessionLifetime = 86400

#  temporary DES key retrieval -> application server
applicationServer_tk_file = open('applicationServer_temp_DES_key.txt', 'r')
applicationServer_tk = applicationServer_tk_file.read(8)
applicationServer_tk_file.close()
print('\nTemporary DES key retrieved: "{}"'.format(applicationServer_tk))

#  public-key retrieval -> centralized certificate authority
centralizedCertificateAuthority_publicKey = RSA.import_key(open("centralizedCertificateAuthority_publicKey.pem").read())

#  connection logic
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as applicationServer:
    applicationServer.bind((HOST, PORT))
    applicationServer.listen()
    print('\nApplication server is running...')
    print('\nAccepted new connection from IP address "{}" - port "{}"...'.format(HOST, PORT))
    centralizedCertificateAuthority, address = applicationServer.accept()
    with centralizedCertificateAuthority:

        #  Application server registration; construction and sending of data
        #  (Application Server -> Centralized Certificate Authority)
        #  Constructed message contents:
        #  [Application Server Temporary Key1(8 chars)||ID of Application Server(9 chars)||Timestamp1(10 digits)
        session_key = get_random_bytes(16)
        timestamp1 = time.time().__trunc__()
        nonEncryptedMessage = applicationServer_tk.__str__() + applicationServer_id + timestamp1.__str__()
        nonEncryptedMessageEncoded = nonEncryptedMessage.encode('utf-8')
        file_out = open("encrypted_data.bin", "wb")
        RSA_cipher = PKCS1_OAEP.new(centralizedCertificateAuthority_publicKey)
        encryptedSessionKey = RSA_cipher.encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(nonEncryptedMessageEncoded)
        print('\nSent ciphertext: "{}"'.format(ciphertext))
        [file_out.write(x) for x in (encryptedSessionKey, cipher_aes.nonce, tag, ciphertext)]
        file_out.close()
        time.sleep(5)

        #  Application server registration; reception and parsing of message contents
        #  (Centralized Certificate Authority -> Application Server)
        #  Expected message contents:
        #  [Application Server Public-Key||Application Server Private-Key +\
        #  ||Certificate||Application Server ID||Timestamp2]

        file_in = open("encrypted_data.bin", "rb")
        encryptedSessionKey, nonce1, tag1, ciphertext1 = \
            [file_in.read(x) for x in (centralizedCertificateAuthority_publicKey.size_in_bytes(), 16, 16, -1)]
        RSA_cipher1 = PKCS1_OAEP.new(centralizedCertificateAuthority_publicKey)
        cipher_aes1 = AES.new(session_key, AES.MODE_EAX, nonce1)
        print('\nReceived ciphertext: "{}"'.format(ciphertext1))
        data = cipher_aes1.decrypt_and_verify(ciphertext1, tag1)
        dataDecoded = data.decode("utf-8")
        receivedTimestamp2 = dataDecoded[-10:]
        receivedApplicationServerID = dataDecoded[-19:-10]
        receivedApplicationServerPublicKey = dataDecoded[0:461]
        receivedApplicationServerPrivateKey = dataDecoded[461:2164]
        print('\nReceived public-key for independent usage: "{}"'.format(receivedApplicationServerPublicKey))
        print('\nReceived private-key for independent usage: "{}"'.format(receivedApplicationServerPrivateKey))
        certificate = dataDecoded.replace(receivedTimestamp2, '').replace(receivedApplicationServerPublicKey, '').\
            replace(receivedApplicationServerPrivateKey, '').replace(receivedApplicationServerID, '')
        print('\n certificate = "{}"'.format(certificate))







