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
centralizedCertificateAuthority_sk = 'radiance'  # private key
sessionLifetime = 86400

#  key pair generation (private and public) -> centralized certificate authority
centralizedCertificateAuthority_keyPair = RSA.generate(2048)
centralizedCertificateAuthority_privateKey = centralizedCertificateAuthority_keyPair.export_key()
file_out = open("centralizedCertificateAuthority_privateKey.pem", "wb")
file_out.write(centralizedCertificateAuthority_privateKey)
file_out.close()
centralizedCertificateAuthority_publicKey = centralizedCertificateAuthority_keyPair.publickey().export_key()
file_out = open("centralizedCertificateAuthority_publicKey.pem", "wb")
file_out.write(centralizedCertificateAuthority_publicKey)
file_out.close()

time.sleep(5)

#  connection logic
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as applicationServer:
    applicationServer.connect((HOST, PORT))
    print('\nCentralized certificate authority is running...')
    print('\nConnected to application server using IP address "{}" - port "{}"...'.format(HOST, PORT))

    #  Application server registration; reception and parsing of data
    #  (Application Server -> Centralized Certificate Authority)
    #  Expected message contents:
    #  [Application Server Temporary Key1(8 chars)||ID of Application Server(9 chars)||Timestamp1(10 digits)
    file_in = open("encrypted_data.bin", "rb")
    centralizedCertificateAuthority_privateKey =\
        RSA.import_key(open("centralizedCertificateAuthority_privateKey.pem").read())
    encryptedSessionKey, nonce, tag, ciphertext =\
        [file_in.read(x) for x in (centralizedCertificateAuthority_privateKey.size_in_bytes(), 16, 16, -1)]
    RSA_cipher = PKCS1_OAEP.new(centralizedCertificateAuthority_privateKey)
    session_key = RSA_cipher.decrypt(encryptedSessionKey)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    print('\nReceived ciphertext: "{}"'.format(ciphertext))
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    dataDecoded = data.decode("utf-8")
    receivedApplicationServer_temp_DES_key = dataDecoded[0:8]
    print('\nTemporary DES key extracted from application server: "{}"'.format(receivedApplicationServer_temp_DES_key))
    receivedApplicationServer_id = dataDecoded[8:17]
    receivedApplicationServer_timestamp = dataDecoded[17:27]

    #  Generation of public and private key to be provided to the application server for independent usage
    applicationServer_keyPair = RSA.generate(2048)
    applicationServer_privateKey = applicationServer_keyPair.export_key()
    file_out = open("applicationServer_privateKey.pem", "wb")
    file_out.write(applicationServer_privateKey)
    file_out.close()
    applicationServer_publicKey = applicationServer_keyPair.publickey().export_key()
    file_out = open("applicationServer_publicKey.pem", "wb")
    file_out.write(applicationServer_publicKey)
    file_out.close()
    print('\nPublic-key generated for application server: "{}"'.format(applicationServer_publicKey.__str__()))
    print('\nPrivate-key generated for application server: "{}"'.format(applicationServer_privateKey.__str__()))

    #  Application server registration; certificate generation
    message = applicationServer_id + centralizedCertificateAuthority_id + applicationServer_publicKey.__str__()
    h = SHA256.new(message.encode("utf-8"))
    signature = pkcs1_15.new(centralizedCertificateAuthority_privateKey).sign(h)
    RSA_cipher = PKCS1_OAEP.new(centralizedCertificateAuthority_privateKey)
    certificate = signature
    print('\nCertificate generated for application server: "{}"'.format(certificate.__str__()))

    #  Application server registration; construction and sending of message contents
    #  (Centralized Certificate Authority -> Application Server)
    #  Constructed message contents:
    #  [Application Server Public-Key||Application Server Private-Key||Certificate||Application Server ID||Timestamp2]
    timestamp = time.time().__trunc__()
    nonEncryptedMessage = applicationServer_publicKey.__str__() + applicationServer_privateKey.__str__() +\
        certificate.__str__() + applicationServer_id + timestamp.__str__()
    nonEncryptedMessageEncoded = nonEncryptedMessage.encode("utf-8")
    cipher_aes1 = AES.new(session_key, AES.MODE_EAX, nonce)
    ciphertext1, tag1 = cipher_aes1.encrypt_and_digest(nonEncryptedMessageEncoded)
    file_out = open("encrypted_data.bin", "wb")
    file_out.flush()
    [file_out.write(x) for x in (encryptedSessionKey, cipher_aes1.nonce, tag1, ciphertext1)]
    file_out.close()
    print('\nSent ciphertext: "{}"'.format(ciphertext1))
    print('\nCentralized certificate authority will now disconnect from the application server...')







