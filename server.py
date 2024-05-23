import socket, json
from model import get_model
import threading
from data import encode_layer, decode
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, os, pickle
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from SmartContract.server_smart_contract import ServerSmartContract
import sqlite3
import numpy as np
from data import get_data
import threading
from sklearn.utils import shuffle
from utils import decode_dict, encode_dict

from utils import ClientValidationContainer

class Server:

    def __init__(self):
        
        #private and public keys
        random = Random.new().read
        RSAkey = RSA.generate(4096, random)
        self.public = RSAkey.publickey().exportKey()
        self.private = RSAkey.exportKey()

        tmpPub = hashlib.sha3_256(self.public)
        self.server_hash_public = tmpPub.hexdigest()

        #setting up aes
        self.AESKey = None
        self.delimiter_bytes = b'###'
        self.smart_contract_data = None
        self.smart_contract_abi = None
        self.smart_contract_address = None
        self.account_address = None

        self.eightByteClient = os.urandom(8)
        sess = hashlib.sha3_256(self.eightByteClient)
        self.session_client = sess.hexdigest()
        self.AESKeyClient = bytes(self.eightByteClient + self.eightByteClient[::-1])
        
        self.host = '127.0.0.1'
        self.port = 12345         
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket_client = None

        self.gateway_host = '127.0.0.1'
        self.gateway_port = 1234    

        #connected clients get append to list
        self.connected_nodes = list()
        self.connected_clients = set()
        self.pending_nodes = list()
        self.average_weights = {}

        self.required_nodes = 1
        self.max_rounds = 2
        
        self.check = False
        self.training_round = 0
        self.epochs = 1

        #model which gets send to the client
        self.base_global_model = None
        self.global_model = None
        self.enc_global_model = None
        self.training_complete = threading.Event()

        self.model_weights_list = []

        #set up to encrypt global model
        self.server_model_encode_key = None
        self.server_model_decode_key = None

        self.gateway_public_key = None
        self.hashed_global_model = None
        self.server_smart_contract = None
        self.hashed_server_model_data = None

        #url gets saved in BC, that Client is getting connected to the correct server
        self.connection_url = self.host + ":" + str(self.port)

        self.server_reconnection_id = ""
        self.model_weights_updated = False
        self.average_client_model_weights = None
        self.model_input_lengths_from_server = None

        self.model_results = [None, None]

        self.base_smart_contract = None
        self.aggregate_server_smart_contract = None
        
        self.set_up_database()


    def set_up_database(self):
        
        conn = sqlite3.connect('./data/model_weights.db')
        cursor = conn.cursor()

        #delete table change afterwards!!!
        cursor.execute('''DROP TABLE IF EXISTS model_weights''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS model_weights (id INTEGER PRIMARY KEY, data BLOB)''')
        conn.commit()
        conn.close()
        print("Database is set up...")


    #build first gateway connection
    def build_gateway_connection(self):

        self.server_socket.connect((self.gateway_host, self.gateway_port))

        print(f"Verbindung zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")

        gateway_open_thread = self.server_socket.recv(1024)

        if gateway_open_thread == b"OPEN_THREAD":

            self.server_socket.send(b"GATEWAY_READY_FOR_RSA")

            gateway_ready = self.server_socket.recv(1024)

            if gateway_ready == b"GATEWAY_READY_FOR_RSA":

                self.send_rsa_keys()

    
    def send_rsa_keys(self):

        self.server_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

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
    

    def aes_server_encoding(self, data):

        iv = os.urandom(16)

        # Create AES cipher object in CFB mode
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Return IV concatenated with encrypted data
        return iv + encrypted_data

    
    def aes_server_decoding(self, data):

        iv = data[:16]

        # Create AES cipher object in CFB mode
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def verify_server_keys(self):
        
        serverPH = self.server_socket.recv(4096)

        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey


    def get_gateway_respond(self):
        
        tmpHash, GatewayPublicKeyHash, GatewayPublicKey = self.verify_server_keys()

        if tmpHash == GatewayPublicKeyHash:

            self.gateway_public_key = GatewayPublicKey

            self.server_socket.send("GATEWAY_KEYS_VERIFIED_BY_SERVER".encode('utf-8'))

            #set up AES with Gateway
            received_aes_data = self.server_socket.recv(2048)

            hashOfEight, session, eightByte = self.set_aes_encryption(received_aes_data)

            if hashOfEight  == session: 

                self.AESKey = bytes(eightByte + eightByte[::-1])

                #sends back shared secret if it´s correct
                public_key = RSA.import_key(GatewayPublicKey)
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_data = cipher.encrypt(eightByte)

                self.server_socket.send(encrypted_data)

                gateway_aes_msg = self.server_socket.recv(2048)
                decrypted_aes_data = self.aes_server_decoding(gateway_aes_msg)

                if decrypted_aes_data == b"AES_READY":
                    
                        aes_verified = self.aes_server_encoding(b"AES_VERIFIED")
                        self.server_socket.send(aes_verified)

                        get_connection_url = self.server_socket.recv(4096)
                        get_connection_url = self.aes_server_decoding(get_connection_url)

                        if b"GET_CONNECTION_URL" == get_connection_url:

                            #sending url of server to save in BC
                            connection_url = self.aes_server_encoding(self.connection_url.encode("utf-8"))
                            self.server_socket.send(connection_url)

                            gateway_respond = self.server_socket.recv(4096)

                            if gateway_respond:
                                
                                read_smart_contract = self.aes_server_encoding(b"READY_SMART_CONTRACT")
                                self.server_socket.send(read_smart_contract)

                                #aggregate-server gets smart contract
                                smart_contract_data_bytes = self.server_socket.recv(4096)
                                smart_contract_data = self.aes_server_decoding(smart_contract_data_bytes)
                                self.smart_contract_data = pickle.loads(smart_contract_data)
                                
                                print("***********************************************************")
                                print("")
                                print("Server Smart Contract: ", self.smart_contract_data)
                                print("")
                                print("***********************************************************")

                                read_smart_contract = self.aes_server_encoding(b"RECEIVED_SMART_CONTRACT_DATA")
                                self.server_socket.send(read_smart_contract)
                                
                                #save account adress to handle bc actions later on
                                self.account_address = self.smart_contract_data["AccountAddress"]

                                #server gets reconnection ID
                                server_reconnection_id = self.server_socket.recv(4096)
                                server_reconnection_id = self.aes_server_decoding(server_reconnection_id)
                                
                                self.server_reconnection_id = server_reconnection_id.decode("utf-8")

                                self.set_up_model()

        else:
            print("No Gateway Respond")    


    def train_pre_build_server_model(self):

        #model weights gets overwritten to cut the length
        overwritten_X_train = self.X_train[:(len(self.X_train)-10000)]
        overwritten_y_train = self.y_train[:(len(self.y_train)-10000)]
        overwritten_X_test = self.X_test[:(len(self.X_test)-10000)]
        overwritten_y_test = self.y_test[:(len(self.y_test)-10000)]

        self.base_global_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.base_global_model.fit(overwritten_X_train, overwritten_y_train, epochs=self.epochs, batch_size=32,
                                    validation_data=(overwritten_X_test, overwritten_y_test))
        
        server_test_loss, server_test_accuracy = self.base_global_model.evaluate(overwritten_X_test, overwritten_y_test)

        print()
        print("Server Results of the example ML-Model:")
        print()
        print("Test Loss:", server_test_loss)
        print("Test Accuracy:", server_test_accuracy)
        print()

        return server_test_loss, server_test_accuracy


    #the server builds by it´s own a model to have something to compare to the results of the clients
    def build_pre_trained_server_model(self):

#sind noch dieselben daten wie beim client
        #the server loads his own independent data to compare it with the other clients
        X_train, y_train, X_test, y_test = get_data()

        #shuffle the data to have a difference to the client data
        self.X_train, self.y_train = shuffle(X_train, y_train)
        self.X_test, self.y_test = shuffle(X_test, y_test)

        #server is commanding a specific datasize
#werde künstlich verkürzt um einen unterschied zu haben!
        model_input_lengths_from_server = {
            "X_train": (len(self.X_train)-10000),
            "y_train": (len(self.y_train)-10000),
            "X_test": (len(self.X_test)-10000),
            "y_test": (len(self.y_test)-10000)
        }

        model_input_lengths_from_server = pickle.dumps(model_input_lengths_from_server)

        return model_input_lengths_from_server


    #after getting smart contract server is setting up the model
    def set_up_model(self):

        #init the model
        base_global_model = get_model()
        self.base_global_model = base_global_model

        server_model_data = {
                "model_architecture": base_global_model.to_json(),
                "model_weights": encode_layer(base_global_model.get_weights()),
            }
        
        self.hashed_server_model_data = self.hash_model(server_model_data).hexdigest()
        
        server_model_data_json = json.dumps(server_model_data)
        self.global_model = pickle.dumps(server_model_data_json)

        #model gets hashed
        hashed_global_model = self.hash_model(self.global_model)
        self.hashed_global_model = hashed_global_model.hexdigest()

        #set up keys to encrypt and decrypt model and hash
        #model gets encrypted by ServerModelEncodeKey
        self.server_model_decode_key, self.enc_global_model = self.encrypt_global_model(self.global_model)

        #encrypted Model and Hash of unencrypted Model
        enc_model_data_dict = {'EncryptedModel': f'{self.enc_global_model}',
                                'ModelHash': f'{self.hashed_global_model}'}
        
        enc_model_data_bytes = encode_dict(enc_model_data_dict)
        
        #encrypted model and hash get encrypted by random key Enc(EncModel + Hash)
        decrypt_dict_key, encrypted_model_hash_dict = self.encrypt_final_global_model_hash_dict(enc_model_data_bytes)

        #this random key gets encrypted by PK from gateway server
        pk_enc_encrypt_key = self.encrypt_decrypt_dict_key(decrypt_dict_key)

        #encrypted model and hash get send to gateway
        pk_enc_encrypt_key = self.aes_server_encoding(pk_enc_encrypt_key)
        self.server_socket.send(pk_enc_encrypt_key)

        gateway_got_enc_encryption_key = self.server_socket.recv(1024)
        gateway_got_enc_encryption_key = self.aes_server_decoding(gateway_got_enc_encryption_key)

        if gateway_got_enc_encryption_key == b"GOT_ENC_ENCRYPTION_KEY":

            encrypted_model_hash_dict = self.aes_server_encoding(encrypted_model_hash_dict)
            self.server_socket.sendall(encrypted_model_hash_dict)
            
            print("Sending enc model dict to gateway...")
            
            gateway_got_enc_model = self.server_socket.recv(1024)
            gateway_got_enc_model = self.aes_server_decoding(gateway_got_enc_model)

            if gateway_got_enc_model == b"GOT_ENC_MODEL_DATA":
                    
                    get_smart_contract = self.aes_server_encoding(b"GET_SMART_CONTRACT")
                    self.server_socket.send(get_smart_contract)

                    #getting base smart contract
                    enc_serialized_base_smart_contract = self.server_socket.recv(16384)
                    serialized_base_smart_contract = self.aes_server_decoding(enc_serialized_base_smart_contract)
                    gateway_smart_contract_dict = pickle.loads(serialized_base_smart_contract)

                    self.gateway_smart_contract = ServerSmartContract().rebuild_smart_contract(gateway_smart_contract_dict)

                    print("Gateway Smart Contract Set Up!")

                    received_smart_contract = self.aes_server_encoding(b"RECEIVED_BASE_SMART_CONTRACT")
                    self.server_socket.send(received_smart_contract)

                    #getting server smart contract from gatewayserver
                    enc_serialized_aggregate_server_smart_contract = self.server_socket.recv(16384)
                    serialized_aggregate_server_smart_contract = self.aes_server_decoding(enc_serialized_aggregate_server_smart_contract)
                    server_smart_contract_dict = pickle.loads(serialized_aggregate_server_smart_contract)

                    self.aggregate_server_smart_contract = ServerSmartContract().rebuild_smart_contract(server_smart_contract_dict)

                    print("Server Smart Contract Set Up!")

                    #hash the enc model
                    encrypted_model_hash = self.hash_model(self.enc_global_model)

                    print("Final Account Address", self.account_address)


                    server_model_set_up = ServerSmartContract().set_up_global_model(
                                                                                encrypted_model_hash.hexdigest(),
                                                                                self.hashed_global_model,
                                                                                self.account_address,
                                                                                self.gateway_smart_contract
                                                                                )
                    
                    if server_model_set_up:

                        updated_server_smart_contract = ServerSmartContract().get_aggregate_server(
                                                                            self.account_address,
                                                                            self.gateway_smart_contract
                                                                        )

                        print("***********************************************************")
                        print("")
                        print("Updated Server Smart Contract: ", updated_server_smart_contract)
                        print("")
                        print("***********************************************************")

                        self.run_server()


    #hash the model
    def hash_model(self, global_model):
        
        hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
        return hashed_global_model
    

        #encrypt globale model with server model encode key
    def encrypt_global_model(self, global_model):
        
        server_model_decode_key = Fernet.generate_key()
        cipher = Fernet(server_model_decode_key)
        encrypted_global_model = cipher.encrypt(global_model)
        
        return server_model_decode_key, encrypted_global_model
    

    #encrypt the model and it´s hash with a random generated key
    def encrypt_final_global_model_hash_dict(self, enc_model_data):

        encrypt_dict_key = Fernet.generate_key()
        cipher = Fernet(encrypt_dict_key)
        encrypted_json_model_data = cipher.encrypt(enc_model_data)

        return encrypt_dict_key, encrypted_json_model_data


    def encrypt_decrypt_dict_key(self, encrypt_key):

        #encrypt key, which encryptes Model and Hash with GatewayPublicKey
        key = RSA.importKey(self.gateway_public_key)
        cipher = PKCS1_OAEP.new(key)
        pk_enc_encrypt_key = cipher.encrypt(encrypt_key)

        return pk_enc_encrypt_key


    #client get´s after reconnection a random byte sequence encrypted in AES. If client is sending back the correct byte sequence, the client
    #is authenticated...
    def test_gateway_connection(self, client_socket):

        random_bytes = os.urandom(10)
        random_bytes_hash = self.hash_model(random_bytes)
        random_bytes_hash = random_bytes_hash.hexdigest()

        print("Server Connection Test Hash", random_bytes_hash)

        random_test_byte_sequence = self.aes_server_encoding(random_bytes)
        client_socket.send(random_test_byte_sequence)

        server_test_byte_response = client_socket.recv(2048)
        server_test_byte_response = self.aes_server_decoding(server_test_byte_response)

        if str(random_bytes_hash) == str(server_test_byte_response.decode("utf-8")):

            print("Gateway is successfully reconnected with Server...")

            server_waiting_model_weights = self.aes_server_encoding(b"SERVER_WAITING_MODEL_WEIGHTS")
            client_socket.send(server_waiting_model_weights)

            #getting the model weights from the gateway server
            self.get_client_model_weights(client_socket)


    # sever is getting the model weights from the client via the gateway server
    def get_client_model_weights(self, client_socket):

            enc_client_model_weights = client_socket.recv(65536)
            enc_client_model_weights = self.aes_server_decoding(enc_client_model_weights)

            final_client_model_weights = pickle.loads(enc_client_model_weights)

            client_device_key = final_client_model_weights["DeviceKey"]
            client_model_weights = final_client_model_weights["ModelWeights"]

            self.verify_client_model_weights(client_device_key, client_model_weights, client_socket)

            
    #send model weights back to gateway
    def send_updated_model_weights(self, client_socket):
        
        server_model_weights = {
            "ServerAccountAddress": f"{self.account_address}",
            "ServerModelWeights": self.average_client_model_weights
        }

        average_client_model_weights = pickle.dumps(server_model_weights)
        updated_client_model_weights = self.aes_server_encoding(average_client_model_weights)
        client_socket.send(updated_client_model_weights)

        received_gateway_model_weights = client_socket.recv(2048)
        received_gateway_model_weights = self.aes_server_decoding(received_gateway_model_weights)

        if received_gateway_model_weights == b"GATEWAY_RECEIVED_SERVER_MODEL_WEIGHTS":

            #if sending sucessfull, when model weights were not changed!
            self.average_client_model_weights = None

            #ending round of training
            self.training_round +=1

            print()
            print("Max Rounds of Training: ", self.max_rounds, "Round Number: ", int(self.training_round))
            print()

#grund training abzubrechen
            if int(self.max_rounds) <= int(self.training_round):
                
                server_waiting_model_weights = self.aes_server_encoding(b"TRAINING_FINISHED")
                client_socket.send(server_waiting_model_weights)

                print("All Rounds were finished successfully...")
                self.close_connection()

            else:

                server_waiting_model_weights = self.aes_server_encoding(b"SERVER_INIT_NEXT_TRAINING_ROUND")
                client_socket.send(server_waiting_model_weights)
                #close old connection
                self.close_connection()

                #reopen the server again for connections
                self.run_server()


    #checks if client really exists in BC and if model weights has changed on Serverside
    def verify_client_model_weights(self, client_device_key, client_model_weights, client_socket):
        
        client_smart_contract_model_weights= ServerSmartContract().get_client_model_weights_server(client_device_key,
                                                                                        self.account_address,
                                                                                        self.gateway_smart_contract)

        hashed_client_model_weights = self.hash_model(client_model_weights)

        if str(client_smart_contract_model_weights["ModelWeightsHash"]) == str(hashed_client_model_weights.hexdigest()):

            print()
            print("Server Verification. Modelweights were not changed")
            print()
            print("Client Smart Contract: ", client_smart_contract_model_weights)

            #save final_client_model_weights
            self.save_client_model_weights(client_model_weights, client_socket)

    #save the client model weights in the database
    def save_client_model_weights(self, client_model_weights, client_socket):

#!!!!Das PROBLEM
#delete model weights just for now!

        serialized_model_weight_arrays = [pickle.dumps(arr) for arr in client_model_weights]

        conn = sqlite3.connect('./data/model_weights.db')
        cursor = conn.cursor()
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        for serialized_array in serialized_model_weight_arrays:
            cursor.execute('''INSERT INTO model_weights (data) VALUES (?)''', (serialized_array,))

        print("Insert into database...")

        conn.commit()
        conn.close()

#hier warten bis genug model gewichte gesammelt wurden!

        #at specific amount of clients modelweights get aggregated
        self.aggregate_client_model_weights(client_socket)


    #get the save model weights of client in Database
    def get_model_weights(self):

        conn = sqlite3.connect('./data/model_weights.db')
        cursor = conn.cursor()

        cursor.execute('''SELECT data FROM model_weights''')
        serialized_model_weights_arrays = cursor.fetchall()

        final_client_model_weights = []

        for serialized_array in serialized_model_weights_arrays:

            serialized_data = serialized_array[0]  
            array = pickle.loads(serialized_data) 
            final_client_model_weights.append(array)
  
        conn.commit()
        conn.close()

#delete old model_weights have to change afterwards
        self.set_up_database()

        return final_client_model_weights


    #loads the model weights from the database and aggregate them
    def aggregate_client_model_weights(self, client_socket):

        client_model_weights = self.get_model_weights()

        client_model_weights_list = [client_model_weights]

        average_client_model_weights = [
                np.mean([weights[i] for weights in client_model_weights_list], axis=0)
                for i in range(len(client_model_weights_list[0]))
        ]

        self.set_aggregated_model_weights(average_client_model_weights, client_socket)


    #update model weights in BC
    def set_aggregated_model_weights(self, average_client_model_weights, client_socket):

        average_client_model_weights_hash = self.hash_model(average_client_model_weights)
        average_client_model_weights_hash = average_client_model_weights_hash.hexdigest()

        smart_contract_global_model_weights = ServerSmartContract().set_aggregated_model_weights(
                                                                                    average_client_model_weights_hash,
                                                                                    self.account_address,
                                                                                    self.gateway_smart_contract)
        

        #return updated model weights to gateway
        self.average_client_model_weights = average_client_model_weights

        self.send_updated_model_weights(client_socket)

    
############### Client Section ####################

    #starts the server to get connected with clients
    def run_server(self):

        self.server_socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket_client.bind((self.host, self.port))
        self.server_socket_client.listen()
        print()
        print(f"Server auf {self.host}:{self.port}")
        print()

        self.get_client_request()
    

    #get request from client
    def get_client_request(self):

        try:

                client_socket, client_address = self.server_socket_client.accept()
                
                print(f"Verbindung von {client_address}")

                #checks if gateway or client is connecting
                connection_request = client_socket.recv(2048)

                if connection_request != b"CLIENT_READY_FOR_RSA":

                    #checks if gateway will reconnect
                    if connection_request == b"GATEWAY_READY_FOR_RECONNECTION":

                        self.test_gateway_connection(client_socket)

                else:

                    client_socket.send(b"SERVER_READY_FOR_RSA")

                    tmpHash, clientPublicHash, ClientPublicKey = self.verify_client_keys(client_socket)

                    if str(tmpHash) == str(clientPublicHash):
                
                        self.build_client_threats(client_socket, ClientPublicKey, client_address)
            
        except KeyboardInterrupt:
            print("Server wurde beendet.")

    
    def build_client_threats(self, client_socket, client_public_key, client_address):

            # Client zur Client-Liste hinzufügen
            self.connected_clients.add(client_socket)
            self.connected_nodes.append(client_address)

            # Mehrere Clients handhaben
            client_thread = threading.Thread(target=self.send_server_keys, args=(client_socket, client_address, client_public_key, ))
            client_thread.start()
    


    #client sends its public key and it´s hashed. Here it gets checked
    def verify_client_keys(self, client_socket):
        
        clientPH = client_socket.recv(4096)
        split = clientPH.split(self.delimiter_bytes)

        ClientPublicKey = split[0].decode('utf-8')
        clientPublicKeyHash = split[1].decode('utf-8')

        cleanedClientPublicKey = ClientPublicKey.replace("\r\n", '')
        cleanedClientPublicKeyHash = clientPublicKeyHash.replace("\r\n", '')

        tmpClientPublic_bytes = cleanedClientPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpClientPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedClientPublicKeyHash, ClientPublicKey
    

    #set up aes encryption for communication    
    def build_server_client_aes_encryption(self, client_public_key):

        session_bytes = self.session_client.encode('utf-8')

        #encode with publickey from client
        key = RSA.importKey(client_public_key)
        cipher = PKCS1_OAEP.new(key)
        fSend = self.eightByteClient + self.delimiter_bytes + session_bytes
        fSendEnc = cipher.encrypt(fSend)

        return fSendEnc
    
    
    #encode aes messages for client
    def aes_client_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data


    #decode aes messages from client
    def aes_client_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    #sending server keys to client
    def send_server_keys(self,  client_socket, client_address, ClientPublicKey):

        #after receiving client keys, server sends its keys back
        client_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

        self.get_participant_data(client_socket, client_address, ClientPublicKey)

    
    def get_participant_data(self, client_socket, client_address, client_public_key):

        client_ack_server_keys = client_socket.recv(1024)

        #wait for response before building session keys
        if client_ack_server_keys == b"SERVER_KEYS_VERIFIED_BY_CLIENT":

            #after exchanging rsa keys, build up aes encryption
            fSendEnc = self.build_server_client_aes_encryption(client_public_key)
            client_socket.send(bytes(fSendEnc + self.delimiter_bytes + self.public))

            clientPH = client_socket.recv(4096)

            if len(clientPH) > 0:

                private_key = RSA.import_key(self.private)
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_data_client = cipher.decrypt(clientPH)

                if decrypted_data_client == self.eightByteClient:

                    encrypted_data = self.aes_client_encoding(b"AES_READY_CLIENT_BY_SERVER")
                    client_socket.send(encrypted_data)

                    client_aes_ready = client_socket.recv(4096)
                    client_aes_ready = self.aes_client_decoding(client_aes_ready)

                    #client and server are now ready for fully aes encryption
                    if client_aes_ready == b"CLIENT_AES_READY":

                        print("Client and Server are ready for fully aes encryption")

                        wait_client_smart_contract = self.aes_client_encoding(b"WAIT_CLIENT_SMART_CONTRACT")
                        client_socket.send(wait_client_smart_contract)

                        client_smart_contract = client_socket.recv(4096)
                        client_smart_contract = self.aes_client_decoding(client_smart_contract)
                        client_smart_contract = pickle.loads(client_smart_contract)

                        #server checks if client is in BC from gateway contract
                        server_smart_contract_data = ServerSmartContract().get_client_by_public_key(client_smart_contract["AccountId"],
                                                                                                    self.gateway_smart_contract)

                        if bool(server_smart_contract_data) == True:
                            
                            wait_enc_model_and_id = self.aes_client_encoding(b"WAIT_ENC_MODEL_AND_ID")
                            client_socket.send(wait_enc_model_and_id)
                            
                            enc_client_model_hash = client_socket.recv(4096)
                            enc_client_model_hash = self.aes_client_decoding(enc_client_model_hash)
                            enc_client_model_hash = enc_client_model_hash.decode("utf-8")

                            #checks if model which the client received is the same as send before                            
                            enc = self.hash_model(self.enc_global_model)

                            #if model is verified than ServerModelDecodeKey gets sended
                            if str(enc.hexdigest()) == str(enc_client_model_hash):

                                server_model_decode_key = self.aes_client_encoding(self.server_model_decode_key)
                                client_socket.send(server_model_decode_key)

                                final_model_verification = client_socket.recv(1024)
                                final_model_verification = self.aes_client_decoding(final_model_verification)

                                if final_model_verification == b"RECEIVED_FINAL_MODEL_BY_CLIENT":
                                    
                                    #Data Length Params
                                    #set up the server data to train it´s own model
                                    data_length_params = self.build_pre_trained_server_model()

                                    waiting_client_data_hash = self.aes_client_encoding(b"WAITING_FOR_CLIENT_DATA_HASH")
                                    client_socket.send(waiting_client_data_hash)

                                    #set up training validation container for client
                                    client_data_hash = client_socket.recv(1024)
                                    client_data_hash = self.aes_client_decoding(client_data_hash)

                                    #server fills up the blackbox
                                    client_container = ClientValidationContainer(self.hashed_server_model_data, client_data_hash,
                                                                                  data_length_params, self.public)
                                    
                                    pickled_client_container = pickle.dumps(client_container)
                                    pickled_client_container = self.aes_client_encoding(pickled_client_container)
                                    client_socket.send(pickled_client_container)

                                    #train the server model with its own data to compare it with the client
                                    server_test_loss, server_test_accuracy = self.train_pre_build_server_model()

                                    #receiving the loss and acc from client to compare with server loss and acc
                                    client_model_test_validation = client_socket.recv(4096)
                                    enc_client_model_test_validation = self.aes_client_decoding(client_model_test_validation)

                                    #print("Encrypted Pickle dict", enc_client_model_test_validation, type(enc_client_model_test_validation))

                                    rsa_key = RSA.import_key(self.private)
                                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                                    decrypted_message = cipher_rsa.decrypt(enc_client_model_test_validation)
                                    
                                    client_model_test_validation = pickle.loads(decrypted_message)


                                    if self.validate_client_model_performance(server_test_loss,
                                                                               server_test_accuracy,
                                                                               client_model_test_validation):
                                        

                                        #wait before sending depending on how many clients are connected
                                        if len(self.connected_nodes) >= self.required_nodes:

                                            for client in self.connected_clients:
                                                print(client)

                                                client_accessed = self.aes_client_encoding(b"CLIENT_ACCESSED")
                                                client.send(client_accessed)

                                            self.run_server()

                                        else:

                                            self.run_server()

                                    else:
                                        client_socket.close()        
                                        print("Detected Anomaly in Client Model Result")

                                        #server jumps back to open connection
                                        self.run_server()

                        else:
                            print("Client is not registered!")


#HIER WEITER
    def validate_client_model_performance(self, server_test_loss, server_test_accuracy, client_model_test_validation):

        client_test_loss = client_model_test_validation["ClientTestLoss"]
        client_test_accuracy = client_model_test_validation["ClientTestAccuracy"]

        print()
        print("Compare Server Model and Client Model Results:")
        print()
        print("Server Test loss: ", server_test_loss, "Server Test Accuracy: ", server_test_accuracy)
        print()
        print("Client Test loss: ", client_test_loss, "Client Test Accuracy: ", client_test_accuracy)

        if int(client_test_accuracy) - int(server_test_accuracy) > 0.2 or int(server_test_accuracy) - int(client_test_accuracy) > 0.2:

            return False

        return True


    #close server and client connection
    def close_connection(self):
        self.server_socket.close()
        print("Server Connection closed")
        for client_socket in self.connected_clients:
                client_socket.close()


if __name__ == "__main__":

    server = Server()
    server.build_gateway_connection()