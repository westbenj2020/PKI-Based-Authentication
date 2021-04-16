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
BLOCK_SIZE = 32
client1_id = 'ID-Client1'
applicationServer_id = 'ID-Server'
centralizedCertificateAuthority_id = 'ID-CA'
sessionLifetime = 86400

#  key pair generation (private and public) -> centralized certificate authority
centralizedCertificateAuthority_keyPair = RSA.generate(2048)
centralizedCertificateAuthority_privateKey = centralizedCertificateAuthority_keyPair.export_key()
file_out = open("CCA_centralizedCertificateAuthority_privateKey.pem", "wb")
file_out.write(centralizedCertificateAuthority_privateKey)
file_out.close()
centralizedCertificateAuthority_publicKey = centralizedCertificateAuthority_keyPair.publickey().export_key()
file_out = open("CCA_centralizedCertificateAuthority_publicKey.pem", "wb")
file_out.write(centralizedCertificateAuthority_publicKey)
file_out.close()

#  private-key retrieval -> centralized certificate authority
centralizedCertificateAuthority_privateKey =\
    RSA.import_key(open("CCA_centralizedCertificateAuthority_privateKey.pem").read())

#  connection logic
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as applicationServer:
    applicationServer.connect((HOST, PORT))
    print('\nCentralized certificate authority is running...')
    print('\nConnected to application server using IP address "{}" - port "{}"...'.format(HOST, PORT))

    #  Application server registration; reception and parsing of data (1)
    #  (Application Server -> Centralized Certificate Authority)
    #  Expected message contents:
    #  [Application Server Temporary Key1(8 chars)||ID of Application Server(9 chars)||Timestamp1(10 digits)
    receivedData1 = applicationServer.recv(4096)
    RSA_cipher1 = PKCS1_OAEP.new(centralizedCertificateAuthority_privateKey)
    receivedDataDecrypted1 = RSA_cipher1.decrypt(receivedData1)
    print('\nReceived ciphertext from application server: "{}"'.format(receivedData1))
    receivedDataDecryptedDecoded1 = receivedDataDecrypted1.decode("utf-8")
    upperBoundTempKeyExtract1 = receivedDataDecryptedDecoded1.find('ID-')
    extractedTempKey1 = receivedDataDecryptedDecoded1[0:upperBoundTempKeyExtract1]
    print('\nExtracted temporary key from application server: "{}"'.format(extractedTempKey1))

    #  Generation of public and private key to be provided to the application server for independent usage
    applicationServer_keyPair = RSA.generate(2048)
    applicationServer_privateKey = applicationServer_keyPair.export_key()
    file_out = open("CCA_applicationServer_privateKey.pem", "wb")
    file_out.write(applicationServer_privateKey)
    file_out.close()
    applicationServer_publicKey = applicationServer_keyPair.publickey().export_key()
    file_out = open("CCA_applicationServer_publicKey.pem", "wb")
    file_out.write(applicationServer_publicKey)
    file_out.close()
    print('\nPublic-key generated for application server: "{}"'.format(applicationServer_publicKey.__str__()))
    print('\nPrivate-key generated for application server: "{}"'.format(applicationServer_privateKey.__str__()))

    #  Application server registration; certificate generation (2)
    message = applicationServer_id + centralizedCertificateAuthority_id + applicationServer_publicKey.__str__()
    h = SHA256.new(message.encode("utf-8"))
    signature = pkcs1_15.new(centralizedCertificateAuthority_privateKey).sign(h)
    RSA_cipher2 = PKCS1_OAEP.new(centralizedCertificateAuthority_privateKey)
    certificate = signature
    print('\nCertificate generated for application server: "{}"'.format(certificate.__str__()))

    #  Application server registration; construction and sending of message contents (2)
    #  (Centralized Certificate Authority -> Application Server)
    #  Constructed message contents:
    #  [Application Server Public-Key||Application Server Private-Key||Certificate||Application Server ID||Timestamp2]
    timestamp2 = time.time().__trunc__()
    nonEncryptedMessage2 = applicationServer_publicKey.__str__() + applicationServer_privateKey.__str__() +\
        certificate.__str__() + applicationServer_id + timestamp2.__str__()
    nonEncryptedMessageEncoded2 = nonEncryptedMessage2.encode("utf-8")
    cipher2 = DES.new(extractedTempKey1.encode('utf-8'), DES.MODE_ECB)
    encryptedMessageEncoded2 = cipher2.encrypt(pad(nonEncryptedMessageEncoded2, BLOCK_SIZE))
    print('\nTEST >>> "{}'.format(nonEncryptedMessageEncoded2))
    applicationServer.sendall(encryptedMessageEncoded2)
    print('\nSent ciphertext to application server: "{}"'.format(encryptedMessageEncoded2))
    print('\nCentralized certificate authority will now disconnect from the application server...')







