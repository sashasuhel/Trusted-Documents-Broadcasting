import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

######################################################### Server_Session_key ####################################################

# This function reads the private key and returns it 
def readPrivate(filename):
    with open(filename, "rb") as key_file:
            serverPrivateKey = serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
    return serverPrivateKey

# This function decrypts the received session key using the server's private key from the first function
def decryptSessionKeys(sessionBytes, serverPrivateKeyPath):
    serverPrivateKey = readPrivate(serverPrivateKeyPath)
    sessionKeys = serverPrivateKey.decrypt(sessionBytes,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return sessionKeys

# This function uses the session keys from the above function to decrypt the data received.
def aesDecrypt(aesEncryptedData, sessionKeyBytes, iv, pathToSave):
    mode = AES.new(sessionKeyBytes, AES.MODE_CBC, iv)
    og_data = unpad(mode.decrypt(aesEncryptedData), 16)
    open(pathToSave, 'wb').write(og_data)
    return 0

###############################################################                 #######################################################

# Stream class to handle the buffered data.
class Stream:
    def __init__(self,s):
        self.socket = s
        self.stream = b''

    def get_data(self,n):
        while len(self.stream) < n:
            try:
                data = self.socket.recv(1024)
                if not data:
                    data = self.stream
                    self.stream = b''
                    return data
                self.stream += data
            except:
                print('end of bytes received')
        data,self.stream = self.stream[:n],self.stream[n:]
        return data

    def send_data(self,data):
        self.socket.sendall(data)

    def get_str_data(self):
        try:
            while b'\x00' not in self.stream:
                data = self.socket.recv(1024)
                if not data:
                    return ''
                self.stream += data
        except:
            print('Error occured during reading bytes')
        data,_,self.stream = self.stream.partition(b'\x00')
        return data.decode()

    def send_str_data(self,s):
        if '\x00' in s:
            raise ValueError('string contains delimiter(null)')
        self.socket.sendall(s.encode() + b'\x00')

####################################################### Buffer ###########################################################################

# Receive data from the stream and add it to a variable data until all data is sent. Once all data is received return the data.
def getBytes(file_size, connbuf):
    remaining = file_size
    data = b''
    while remaining:
        chunk_size = 4096 if remaining >= 4096 else remaining
        chunk = connbuf.get_data(chunk_size)
        if not chunk: break
        data += chunk
        remaining -= len(chunk)
    if remaining:
        print('File incomplete.  Missing',remaining,'bytes.')
    else:
        print('File received successfully.')
    return data

# The main function that sets up the server.
def receiveDocuments(ip, port, currentDirectory):
    listen_addr = ip  #'127.0.0.1'
    listen_port = port

    # We use the certificates to establish SSL
    server_cert = 'src/server.cer'          # Server's certificate 
    server_key = 'src/serverKey.pem'        # Server's private key
    ca_cert = 'src/caCertificate.cer'       # CA certificate

    # Verifying certificates to cofirm handshake
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=server_cert, keyfile=server_key)
    context.load_verify_locations(cafile=ca_cert)

    bindsocket = socket.socket()        # Start the socket and being receiving
    bindsocket.bind((listen_addr, listen_port))
    bindsocket.listen(10)
    print("Waiting for client")
    sent=True
    while sent:
        newsocket, fromaddr = bindsocket.accept()       # Accept connection from client
        print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
        conn = context.wrap_socket(newsocket, server_side=True)     # Perform handshake
        print("SSL established. Peer: {}".format(conn.getpeercert()))
        connbuf = Stream(conn)

        # Receive data and decrypt it.
        while True:
            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedSessionKey = getBytes(file_size, connbuf)
            sessionKey = decryptSessionKeys(encryptedSessionKey, server_key)
            print('Received session key: ', sessionKey)

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedIV = getBytes(file_size, connbuf)
            iv = decryptSessionKeys(encryptedIV, server_key)
            print('IV for AES: ', iv)

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedDocument = getBytes(file_size, connbuf)
            document = aesDecrypt(encryptedDocument, sessionKey, iv, currentDirectory+'/sign.txt')

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedDocumentSignature = getBytes(file_size, connbuf)
            document = aesDecrypt(encryptedDocumentSignature, sessionKey, iv, currentDirectory+'/doc.sig')

            file_size = int(connbuf.get_str_data())
            print('File size: ', file_size )
            encryptedx509Certificate = getBytes(file_size, connbuf)
            document = aesDecrypt(encryptedx509Certificate, sessionKey, iv, currentDirectory+'/doc.crt')
            print('Connection closed. Restart client to reconnect.')
            conn.close()
            sent = False

