import socket, json, os, random, time
from data import get_data
from tensorflow.keras.models import model_from_json
from data import decode
import tkinter as tk
from tkinter import * 
import customtkinter
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, pickle
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from SmartContract.client_smart_contract import ClientSmartContract
from utils import decode_dict
import numpy as np

from client_gui.ClientGui import RegistrationPage, GatewaySelectPage, ModelSelectPage


class Client:

    def __init__(self, master):

        self.master = master

        #private and public keys
        random = Random.new().read
        RSAkey = RSA.generate(4096, random)
        self.public = RSAkey.publickey().exportKey()
        self.private = RSAkey.exportKey()

        tmpPub = hashlib.sha3_256(self.public)
        self.client_hash_public = tmpPub.hexdigest()

        #setting up
        self.AESKey = None
        self.AESKeyServer = None

        self.delimiter_bytes = b'###'

        #build up gateway-server connection
        self.gateway_host = '127.0.0.1'
        self.gateway_port = 1234         

        #build up server connection
        self.host = '127.0.0.1'
        self.port = 12345         

        #GUI STUFF
        self.entry = tk.Entry(master)
        self.text = tk.Text(master)
        self.username_entry = tk.Entry(master)
        self.password_entry = tk.Entry(master, show="*")
        self.email_entry = tk.Entry(master)

        #trainingsdata of the client
        self.X_train, self.y_train, self.X_test, self.y_test = get_data()

        self.model = None
        self.epochs = 1
        self.server_data = ""
        self.chunk_size = 4096

        self.model_weights = dict()
        self.client_account_address = None
        self.client_device_key = None

        self.enc_model_hash = None
        self.enc_global_model = b''
        self.model_hash = None
        self.selected_server_connection_url = None

        self.client_server_socket = None
        self.client_socket = None

        self.master = master
        self.client_reconnection_id = ""

        self.has_send_model_weights = False
        self.smart_contract_abi = None
        self.smart_contract_address = None

        self.gateway_smart_contract = None

        self.frames = {}

        #wenn gateway mitrein
        self.entry_point()

    def entry_point(self):

        if self.build_gui(self.master):

            self.show_frame(GatewaySelectPage)

            if self.select_gateway():

                self.build_gateway_connection()

      
    #build first gateway connection
    def build_gateway_connection(self):

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.gateway_host, self.gateway_port))

            print(f"Verbindung zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")

            self.client_socket.send(b"GATEWAY_READY_FOR_RSA")

            gateway_ready = self.client_socket.recv(1024)

            if gateway_ready == b"GATEWAY_READY_FOR_RSA":


                self.show_frame(RegistrationPage)


    def build_gateway_reconnection(self):

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.gateway_host, self.gateway_port))
        print(f"Reconnection zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")

        return True


    def build_gui(self, master):

        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")

        container = tk.Frame(master, width=750, height=500)
        container.pack(side="top", fill="both", expand = True)

        for F in (RegistrationPage, GatewaySelectPage, ModelSelectPage):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        return True


    def show_frame(self, cont):

        frame = self.frames[cont]
        frame.tkraise()


    def change_gui(self):
        root.destroy()

    def select_gateway(self):
        print("called gateway response")
        return True
 

    def send_register_data(self):
        print("called send register data")
        self.show_frame(ModelSelectPage)


    def select_ml_model(self):

        message = self.public + self.delimiter_bytes + self.client_hash_public.encode('utf-8')
        self.client_socket.send(message)   

        print("Start")
        self.get_gateway_respond() 


    def set_aes_encryption(self, received_aes_data):

            splitServerSessionKey = received_aes_data.split(self.delimiter_bytes)

            fSendEnc = splitServerSessionKey[0]
            serverPublic = splitServerSessionKey[1]

            #encode data with private key
            private_key = RSA.import_key(self.private)
            cipher = PKCS1_OAEP.new(private_key)
            fSend = cipher.decrypt(fSendEnc)

            #eightbyte is the shared secret
            splittedDecrypt = fSend.split(self.delimiter_bytes)
            eightByte = splittedDecrypt[0]
            hashOfEight = splittedDecrypt[1].decode("utf-8")

            sess = hashlib.sha3_256(eightByte)
            session = sess.hexdigest()

            server_public_key = hashlib.sha3_256(serverPublic)
            server_public_hash = server_public_key.hexdigest()

            return hashOfEight, session, eightByte
    
            
    #verifying gateway keys
    def verify_gateway_keys(self):
        
        serverPH = self.client_socket.recv(4096)
        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey
    
    
    def aes_client_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def aes_client_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data


    def get_gateway_respond(self):
        
        tmpHash, GatewayPublicKeyHash, GatewayPublicKey = self.verify_gateway_keys()

        if tmpHash == GatewayPublicKeyHash:

            self.client_socket.send("GATEWAY_KEYS_VERIFIED_BY_CLIENT".encode('utf-8'))
            print("Gatewaykeys verified by Client")
            
            received_aes_data = self.client_socket.recv(2048)

            hashOfEightGateway, session, eightByteGateway = self.set_aes_encryption(received_aes_data)

            if hashOfEightGateway == session: 

                self.AESKey = bytes(eightByteGateway + eightByteGateway[::-1])

                #sends back shared secret if it´s correct
                public_key = RSA.import_key(GatewayPublicKey)
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_data = cipher.encrypt(eightByteGateway)

                self.client_socket.send(encrypted_data)

                gateway_aes_msg = self.client_socket.recv(2048)
                decrypted_aes_data = self.aes_client_decoding(gateway_aes_msg)

                if decrypted_aes_data == b"AES_READY_CLIENT":
                        
                        aes_verified = self.aes_client_encoding(b"AES_VERIFIED_CLIENT")
                        self.client_socket.send(aes_verified)

                        gateway_set_contract = self.client_socket.recv(2048)
                        gateway_set_contract = self.aes_client_decoding(gateway_set_contract)

                        if gateway_set_contract == b"SET_CLIENT_SMART_CONTRAT":

                            ready_flag_smart_contract = self.aes_client_encoding(b"READY_SMART_CONTRACT")
                            self.client_socket.send(ready_flag_smart_contract)

                            smart_contract_data_bytes = self.client_socket.recv(4096)
                            smart_contract_data = self.aes_client_decoding(smart_contract_data_bytes)

                            self.smart_contract_data = pickle.loads(smart_contract_data)

                            print("*************************************************")
                            print("Client Smart Contract: ", self.smart_contract_data)
                            print("*************************************************")

                            received_smart_contract = self.aes_client_encoding(b"RECEIVED_SMART_CONTRACT")
                            self.client_socket.send(received_smart_contract)

                            #getting smart contract from gateway to work
                            enc_serialized_base_smart_contract = self.client_socket.recv(32768)
                            serialized_base_smart_contract = self.aes_client_decoding(enc_serialized_base_smart_contract)
                            gateway_smart_contract_dict = pickle.loads(serialized_base_smart_contract)

                            self.gateway_smart_contract = ClientSmartContract().rebuild_smart_contract(gateway_smart_contract_dict)

                            print("Gateway Smart Contract set up!")

                            self.client_device_key = self.smart_contract_data["AccountId"]
                            self.client_account_address = self.smart_contract_data["AccountAddress"]
            
                            #now client is getting the enc_model and adresses of the servers to control the hash
                            got_smart_contract = self.aes_client_encoding(b"WAIT_FOR_RECON_ID")
                            self.client_socket.send(got_smart_contract)

                            #getting client reconnection id
                            client_reconnection_id = self.client_socket.recv(4096)
                            client_reconnection_id = self.aes_client_decoding(client_reconnection_id)

                            print()
                            print("Client Reconnection ID:", client_reconnection_id.decode("utf-8"))
                            print()

                            self.client_reconnection_id = client_reconnection_id.decode("utf-8")

                            got_reconnection_id = self.aes_client_encoding(b"GOT_RECONNECTION_ID")
                            self.client_socket.send(got_reconnection_id)

                            #client is getting a list of all registered Servers on the BC
                            server_account_addresses = self.client_socket.recv(4096)
                            server_account_addresses = self.aes_client_decoding(server_account_addresses)

                            if server_account_addresses == b"NO_SERVER_AVAILABLE":
                                print("No Server available to connect. Try again later!")
                                self.close_connection()
                                
                            else:

                                try:

                                    server_account_addresses = server_account_addresses.decode("utf-8")
                                    server_account_addresses = json.loads(server_account_addresses)

                                    #checks if server are available
                                except:
                                    print("No Server available to connect!")
                                    self.close_connection()
                               

                                selected_server = self.select_aggregate_server(list(server_account_addresses))
                                selected_server_bytes = str(selected_server).encode("utf-8")
                                selected_server_bytes = self.aes_client_encoding(selected_server_bytes)
                                self.client_socket.send(selected_server_bytes)

                                #smart contract of selected server
                                selected_server_smart_contract = self.client_socket.recv(4096)
                                selected_server_smart_contract = self.aes_client_decoding(selected_server_smart_contract)
                                selected_server_smart_contract = decode_dict(selected_server_smart_contract)

                                print("Selected Server Smart Contract: ", selected_server_smart_contract)

                                #after getting a valid smart contract, the client is connecting with the server
                                if str(selected_server_smart_contract['AccountAddress']) == str(selected_server):

                                    self.selected_server_connection_url = selected_server_smart_contract['ConnectionUrl']
                                    #to check for server if encrypted model was changed
                                    self.enc_model_hash  = selected_server_smart_contract['EncModel']
                                    #to check for server if orginal model was changed
                                    self.model_hash  = selected_server_smart_contract['ModelHash']

                                    #to check for server if client is registered
                                    #self.client_device_key = selected_server_smart_contract['AccountId']

                                    #Client is getting the encrypted model from the Gateway-Server
                                    #is comparing it with the BC and the Hashes
                                    ready_gateway_model = self.aes_client_encoding(b"READY_GATEWAY_MODEL")
                                    self.client_socket.send(ready_gateway_model)

                                    enc_model_gateway = self.client_socket.recv(65536)
                                    enc_model_gateway = self.aes_client_decoding(enc_model_gateway)

                                    enc_global_model = enc_model_gateway.decode("utf-8")

                                    #sent model and received hash are getting compared
                                    verify_end_model_hash = self.hash_model(enc_global_model)

                                    if str(verify_end_model_hash.hexdigest()) == str(self.enc_model_hash):

                                        print("Hash of Enc Models are the same...")

                                        self.enc_global_model = enc_model_gateway

                                        #connect with server and receiving serverModelEncodeKey
                                        host, port = self.selected_server_connection_url.split(':')

                                        #change GUI while connecting to aggregate server...
                                        self.change_gui()
                                        self.close_connection()
                                        self.build_aggregate_server_connection(host, int(port))
        else:
            print("No Gateway Respond")


    #is selecting a random server address from the list
    def select_aggregate_server(self, server_account_addresses):

        selected_server = random.choice(server_account_addresses)
        return selected_server

    #function to decrypt the ml-model with the servermodeldecodekey
    def decrypt_global_model(self, server_model_decode_key, encrypted_global_model):

        cipher = Fernet(server_model_decode_key)
        decrypted_global_model = cipher.decrypt(encrypted_global_model)
        return decrypted_global_model

    
    #hash the model    
    def hash_model(self, global_model):
        
        hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
        return hashed_global_model


    #build connection to aggregate server
    def build_aggregate_server_connection(self, host, port):

        self.client_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_server_socket.connect((host, port))

        print(f"Verbindung zum Server {self.host}:{self.port} hergestellt")

        self.client_server_socket.send(b"CLIENT_READY_FOR_RSA")

        print(1)

        server_ready = self.client_server_socket.recv(1024)

        print(2)

        if server_ready == b"SERVER_READY_FOR_RSA":

            self.send_aggregate_server_data()


    #verifying server keys
    def verify_server_keys(self):
        
        serverPH = self.client_server_socket.recv(4096)
        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey
    

    def aes_server_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKeyServer), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def aes_server_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKeyServer), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data
    

    def send_aggregate_server_data(self):

        #client publickey with its hash gets send
        self.client_server_socket.send(self.public + self.delimiter_bytes + self.client_hash_public.encode('utf-8'))

        tmpHash, ServerPublicKeyHash, ServerPublicKey = self.verify_server_keys()

        if tmpHash == ServerPublicKeyHash:

            #is changing the gui before getting the model from the aggergate server
            self.client_server_socket.send(b"SERVER_KEYS_VERIFIED_BY_CLIENT")
            print("Serverkeys verified by Client")

            #set up AES with Server
            received_aes_data_server = self.client_server_socket.recv(2048)

            hashOfEightServer, sessionServer, eightByteServer = self.set_aes_encryption(received_aes_data_server)

            if hashOfEightServer == sessionServer: 
                
                self.AESKeyServer = bytes(eightByteServer + eightByteServer[::-1])

                #sends back shared secret if it´s correct
                server_public_key = RSA.import_key(ServerPublicKey)
                cipher_server = PKCS1_OAEP.new(server_public_key)
                encrypted_data = cipher_server.encrypt(eightByteServer)

                self.client_server_socket.send(encrypted_data)

                server_aes_msg = self.client_server_socket.recv(2048)
                decrypted_aes_data_server = self.aes_server_decoding(server_aes_msg)

                #AES Encryption is working
                if decrypted_aes_data_server == b"AES_READY_CLIENT_BY_SERVER":
                    
                    client_aes_ready = self.aes_server_encoding(b"CLIENT_AES_READY")
                    self.client_server_socket.send(client_aes_ready)

                    wait_client_smart_contract = self.client_server_socket.recv(4096)
                    wait_client_smart_contract = self.aes_server_decoding(wait_client_smart_contract)

                    if wait_client_smart_contract == b"WAIT_CLIENT_SMART_CONTRACT":

                        client_contract_data = pickle.dumps(self.smart_contract_data)
                        client_contract_data = self.aes_server_encoding(client_contract_data)
                        self.client_server_socket.send(client_contract_data)

                        wait_enc_model_and_id = self.client_server_socket.recv(1024)
                        wait_enc_model_and_id = self.aes_server_decoding(wait_enc_model_and_id)

                        #sending encrypted model and account ID to server
                        if wait_enc_model_and_id == b"WAIT_ENC_MODEL_AND_ID":
                            
                            enc_model_hash = self.aes_server_encoding(self.enc_model_hash.encode("utf-8"))
                            self.client_server_socket.send(enc_model_hash)

                            #client gets the ServerModelEncodeKey to decrypt finally it´s model
                            server_model_decode_key = self.client_server_socket.recv(1024)
                            server_model_decode_key = self.aes_server_decoding(server_model_decode_key)

                            enc_global_model = self.enc_global_model.decode("utf-8")
                            enc_global_model = enc_global_model[2:-1]
                            enc_global_model = enc_global_model.encode("utf")

                            model = self.decrypt_global_model(server_model_decode_key, enc_global_model)

                            if model:

                                verify_model_hash = self.hash_model(model)

                                #after decrypting the model the hash of the real model gets compared
                                if str(verify_model_hash.hexdigest()) == (self.model_hash):

                                    model_json = pickle.loads(model)
                                    received_server_data = json.loads(model_json)

                                    print("Model is verified! Ready for start training sequence...")

                                    final_model_verification = self.aes_server_encoding(b"RECEIVED_FINAL_MODEL_BY_CLIENT")
                                    self.client_server_socket.send(final_model_verification)

                                    #model_input_lengths_from_server = self.client_server_socket.recv(1024)
                                    #model_input_lengths_from_server = self.aes_server_decoding(model_input_lengths_from_server)

                                    received_model_architecture = received_server_data["model_architecture"]
                                    self.model = model_from_json(received_model_architecture)
                                    self.model.set_weights(decode(received_server_data["model_weights"]))
#
                                    self.model.summary()

                                    waiting_client_data_hash = self.client_server_socket.recv(1024)
                                    waiting_client_data_hash = self.aes_server_decoding(waiting_client_data_hash)

                                    #sending hash of client data...
                                    if waiting_client_data_hash == b"WAITING_FOR_CLIENT_DATA_HASH":

                                        X_concatenated = np.concatenate((self.X_train, self.X_test), axis=0)
                                        y_concatenated = np.concatenate((self.y_train, self.y_test), axis=0)
                                        data_concatenate = np.concatenate((X_concatenated, y_concatenated.reshape(-1, 1)), axis=1)

                                        hashed_client_data = self.hash_model(data_concatenate)
                                        hashed_client_data_hex = hashed_client_data.hexdigest()
                                        b_hashed_client_data = hashed_client_data_hex.encode("utf-8")

                                        #sending hashed data for server container
                                        client_data_hash = self.aes_server_encoding(b_hashed_client_data)
                                        self.client_server_socket.send(client_data_hash)

                                        enc_client_validation_container = self.client_server_socket.recv(65536)
                                        pickled_client_validation_container = self.aes_server_decoding(enc_client_validation_container)
                                        client_validation_container = pickle.loads(pickled_client_validation_container)

                                        server_encrypted_msg = client_validation_container.decapsulate_model(received_server_data,
                                                                                                              data_concatenate,
                                                                                                                self.X_train,
                                                                                                                self.X_test,
                                                                                                                self.y_train,
                                                                                                                self.y_test)
                                    

                                        #send to server the result
                                        send_enc_client_result = self.aes_server_encoding(server_encrypted_msg)
                                        self.client_server_socket.send(send_enc_client_result)

                                        client_allowed = self.client_server_socket.recv(1024)
                                        client_allowed = self.aes_server_decoding(client_allowed)

                                        if client_allowed == b"CLIENT_ACCESSED":

                                            self.start_local_training()
                                        
                                        else:
                                            print("Client cannot access")
                                            self.close_connection()

                                       
        else:
            print("Serverkeys are not verified")

    #starts the training of the client    
    def start_local_training(self):

        print()
        print("Client starts training...")
        print()

        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.model.fit(self.X_train, self.y_train, epochs=self.epochs, batch_size=32, validation_data=(self.X_test, self.y_test))

        self.save_model_weights()


    def save_model_weights(self):   

        model_weights = self.model.get_weights()

        hashed_model_weights = self.hash_model(model_weights)
        hashed_model_weights = hashed_model_weights.hexdigest()

        #check up if DeviceKey makes sense!!!

        model_weights_and_id = {
            "ModelWeights": model_weights,
            "DeviceKey": f"{self.client_account_address}"
        }

        final_model_weights = pickle.dumps(model_weights_and_id)

        #set up model weights into the BC
        self.smart_contract_data  = ClientSmartContract().set_client_model_weights(
                                                                                 hashed_model_weights,
                                                                                 self.client_account_address,
                                                                                 self.gateway_smart_contract)

        print("***********************************************************")
        print("")
        print("Updated Client Smart Contract: ", self.smart_contract_data )
        print("")
        print("***********************************************************")


        #reconnect with gateway server to send model weights
        if self.build_gateway_reconnection():

            self.gateway_reconnection(final_model_weights)


    def gateway_reconnection(self, final_model_weights):

        self.client_socket.send(self.client_reconnection_id.encode("utf-8"))

        print()
        print("Client Reconnection ID", self.client_reconnection_id)
        print()

        #check if when msg just sent back it´s possible to solve the test
        gateway_connection_test = self.client_socket.recv(4096)
        gateway_connection_test = self.aes_client_decoding(gateway_connection_test)
        gateway_connection_test_hash = self.hash_model(gateway_connection_test)

        gateway_connection_test_hash = gateway_connection_test_hash.hexdigest()
        gateway_connection_test_hash = gateway_connection_test_hash.encode("utf-8")

        gateway_connection_test_hash = self.aes_client_encoding(gateway_connection_test_hash)
        self.client_socket.send(gateway_connection_test_hash)

        #get response from gateway with new reconnection id
        new_reconnection_id = self.client_socket.recv(1024)
        new_reconnection_id  = self.aes_client_decoding(new_reconnection_id)
        self.client_reconnection_id = new_reconnection_id.decode("utf-8") 

        print()
        print("New Client Reconnection ID", self.client_reconnection_id)
        print()

        if self.has_send_model_weights == False:
            print("Sending model weights")
            self.send_model_weights(final_model_weights)

        elif self.has_send_model_weights == True:
             print("Receiving Model weights update")
             self.get_updated_model_weights()


    def test_connect(self):
        
        self.close_connection()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        gateway_address = (self.gateway_host, self.gateway_port)

        connected = False

        while not connected:

            try:
                self.client_socket.connect(gateway_address)
                connected = True
                print(f"Reconnection zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")
                return True
            
            except ConnectionRefusedError:
                print("Connection refused, retrying...")
                time.sleep(3)  

            except Exception as e:
                print(f"Error: {e}")
                break  
            

    #sending model weights to gateway
    def send_model_weights(self, final_model_weights):

        ready_send_model_weights = self.aes_client_encoding(b"CLIENT_WILL_SEND_MODEL_WEIGHTS")
        self.client_socket.send(ready_send_model_weights)

        gateway_ready_model_weights = self.client_socket.recv(1024)
        gateway_ready_model_weights  = self.aes_client_decoding(gateway_ready_model_weights)

        if gateway_ready_model_weights == b"GATEWAY_READY_FOR_MODEL_WEIGHTS":

            print("Gateway is waiting for Model Weights")

            final_model_weights = self.aes_client_encoding(final_model_weights)
            self.client_socket.send(final_model_weights)

            gateway_model_weights_received = self.client_socket.recv(1024)
            gateway_model_weights_received  = self.aes_client_decoding(gateway_model_weights_received)

            if gateway_model_weights_received == b"CLIENT_MODEL_WEIGHTS_RECEIVED":

                print()
                print("Gateway received Model Weights")
                print()

                self.has_send_model_weights = True

                #reconnect with gateway server to send model weights
                if self.test_connect():
                    self.gateway_reconnection(final_model_weights)


    #waiting for feedback of gateway if closing or start training again...
    def get_updated_model_weights(self):

        client_waiting_model_weights_update = self.aes_client_encoding(b"CLIENT_WAITING_FOR_MODEL_WEIGHTS_UPDATE")
        self.client_socket.send(client_waiting_model_weights_update)

        updated_server_model_weights = self.client_socket.recv(65536)
        updated_server_model_weights = self.aes_client_decoding(updated_server_model_weights)

        self.set_updated_model_weights(updated_server_model_weights)


    def set_updated_model_weights(self, updated_server_model_weights_pickled):

        updated_server_model_weights_dict = pickle.loads(updated_server_model_weights_pickled)

        server_account_address = updated_server_model_weights_dict["ServerAccountAddress"]
        server_updated_model_weights = updated_server_model_weights_dict["ServerModelWeights"]

        #if model weigths sent from gateway are correct than new model weights get set and the training starts again
        if self.verify_server_model_weights(server_account_address, server_updated_model_weights):
                
                self.has_send_model_weights = False

                if self.model is not None:

                    self.model.set_weights(server_updated_model_weights)

                    self.model.summary()
                    self.start_local_training()


    #checks if client really exists in BC and if model weights has changed
    def verify_server_model_weights(self, server_account_address, server_updated_model_weights):

        server_updated_model_weights_hash = self.hash_model(server_updated_model_weights)
        
        server_smart_contract_model_weights = ClientSmartContract().get_server_model_weights_hash_client(server_account_address,
                                                                                        self.client_account_address,
                                                                                        self.gateway_smart_contract)
        print()
        print("Server Smart Contract", server_smart_contract_model_weights)
        print()

        if str(server_smart_contract_model_weights["ServerModelWeightsHash"]) == str(server_updated_model_weights_hash.hexdigest()):

            print()
            print("Client verified. Global Model Weights from Server were not changed")
            print()
            return True


    def close_connection(self):
        self.client_socket.close()
        print("Client Connection closed")


if __name__ == "__main__":

    root = customtkinter.CTk()
    server = Client(root)
    root.mainloop()
    