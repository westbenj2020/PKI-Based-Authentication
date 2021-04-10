import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac
import time

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
