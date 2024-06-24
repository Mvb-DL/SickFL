import os
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class GatewayEncryption:

    def __init__(self):

        self.eightByte = os.urandom(8)
        sess = hashlib.sha3_256(self.eightByte)
        self.session = sess.hexdigest()

        self.AESKey = bytes(self.eightByte + self.eightByte[::-1])

        #aes for client
        self.eightByteClient = None
        self.AESKeyClient = None
        self.delimiter_bytes = b'###'


    #set up aes encryption for communication    
    def set_aes_encryption(self, server_public_key):

        session_bytes = self.session.encode('utf-8')

        #encode with publickey from client
        key = RSA.importKey(server_public_key)
        cipher = PKCS1_OAEP.new(key)
        fSend = self.eightByte + self.delimiter_bytes + session_bytes
        fSendEnc = cipher.encrypt(fSend)

        return fSendEnc


    #set up aes encryption for communication    
    def set_aes_client_encryption(self, client_public_key):

            self.eightByteClient = os.urandom(8)
            sess = hashlib.sha3_256(self.eightByteClient)
            self.session_client = sess.hexdigest()
            self.AESKeyClient = bytes(self.eightByteClient + self.eightByteClient[::-1])

            session_bytes = self.session_client.encode('utf-8')

            #encode with publickey from client
            key = RSA.importKey(client_public_key)
            cipher = PKCS1_OAEP.new(key)
            fSend = self.eightByteClient + self.delimiter_bytes + session_bytes
            fSendEnc = cipher.encrypt(fSend)

            return fSendEnc


    def aes_encoding(self, data):

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            return iv + encrypted_data


    def aes_decoding(self, data):

            iv = data[:16]
            cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

            return decrypted_aes_data


    #aes encoding for clients
    def aes_client_encoding(self, data):

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            return iv + encrypted_data

    #aes decoding for clients
    def aes_client_decoding(self, data):

            iv = data[:16]
            cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

            return decrypted_aes_data