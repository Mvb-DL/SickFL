import socket, time
import threading, uuid, os
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, pickle, json
from Crypto.Cipher import PKCS1_OAEP
from SmartContract.smart_contract import SmartContract
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils import decode_dict, encode_dict


#build device key to identify registered client
def build_device_key():

    device_key = uuid.uuid4()
    device_key_str = str(device_key)
    return device_key_str


class Server:

    def __init__(self):

        #setting up rsa keys
        random = Random.new().read
        RSAkey = RSA.generate(4096, random)
        self.public = RSAkey.publickey().exportKey()
        self.private = RSAkey.exportKey()
        self.AESKey = None

        tmpPub = hashlib.sha3_256(self.public)
        self.server_hash_public = tmpPub.hexdigest()
        
        self.host = '127.0.0.1'
        self.port = 1234         
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #secure aes for server
        self.eightByte = os.urandom(8)
        sess = hashlib.sha3_256(self.eightByte)
        self.session = sess.hexdigest()

        self.AESKey = bytes(self.eightByte + self.eightByte[::-1])

        #aes for client
        self.eightByteClient = None
        self.AESKeyClient = None

        #connected clients get append to list
        self.connected_client_nodes = list()
        self.connected_clients = set()

        #connected server get append to list
        self.connected_server_nodes = list()
        self.connected_server = set()

        self.open_connections = list()
        self.finished_clients = list()

        #registered server addresses in the BC
        self.server_account_addresses = list()

        self.delimiter_bytes = b'###'

        self.connection_url = self.host + ":" + str(self.port)

        self.encrypted_model = ""
        self.gateway_smart_contract_initiated = False
        self.server_global_model_weights = None

        self.aggregate_server_smart_contract = None
        self.gateway_contract_dict = None

        self.server_busy = False 
        self.required_client_weights = 1
        self.received_connection_weights = 0
        self.client_already_registered = []

        self.lock = threading.Lock()

        self.client_host_port_dict = {}
        self.client_host_port_dict_list = []
        self.last_client = False
        self.client_reconnection_sets = []

        #deploy init smart contract
        gateway_contract, self.gateway_contract_dict = SmartContract(role="Gateway", participant_public_key=self.public
                                                                ).open_contract(contract_path="Test.sol",
                                                                    contract_name="GatewaySetUp")
 
        #contract just for the gateway server
        self.gateway_smart_contract = gateway_contract
        self.gateway_smart_contract_address = self.gateway_smart_contract.address
        self.gateway_smart_contract_abi = self.gateway_smart_contract.abi
        
        print()
        print("Smart Contract Deployed: ", self.gateway_smart_contract_address)
        print()
    

    #start the server
    def run_server(self):

        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)

        print(f"Gateway-Server auf {self.host}:{self.port}")

        if self.gateway_smart_contract_initiated is False:

            #after starting up the gateway server it set up a smart contract to the BC
            if self.init_smart_contract():

                self.server_busy = False
                self.get_participant_request()

        elif self.gateway_smart_contract_initiated:

            self.server_busy = False
            self.get_participant_request()


    #set up smart contract and add an account to BC for Gateway
    def init_smart_contract(self):
         
        gateway_smart_contract_data = SmartContract(role="Gateway", participant_public_key=self.public).set_up_account(
                                                                                    self.gateway_smart_contract,
                                                                                    self.connection_url)
         
        print("***********************************************************")
        print()
        print("Gateway Smart Contract: ", gateway_smart_contract_data)
        print()
        print("***********************************************************")

        self.gateway_smart_contract_initiated = True

        return True
    

    def register_connection(self):
        client_id = str(uuid.uuid4())
        self.open_connections.append(client_id)
        return client_id
    

    #updating new reconnection id
    def update_connection(self, reconnection_id):
        new_reconnection_id = str(uuid.uuid4())
        index_to_replace = self.open_connections.index(reconnection_id)
        self.open_connections[index_to_replace] = new_reconnection_id

        return new_reconnection_id
    

    def auth_reconnection_set(self, client_reconnection_set):

        for clients in self.client_reconnection_sets:

                if clients == client_reconnection_set:

                    return True


    #client get´s after reconnection a random byte sequence encrypted in AES. If client is sending back the correct byte sequence, the client
    #is authenticated...
    def test_client_connection(self, client_socket, reconnection_id):
            
            client_host_port = self.aes_client_encoding(b"SERVER_WAIT_RECONNECTION_CODE")
            client_socket.send(client_host_port)

            client_reconnection_set = client_socket.recv(2048)
            client_reconnection_set = self.aes_client_decoding(client_reconnection_set)
            client_reconnection_set = pickle.loads(client_reconnection_set)

            #updated reonnection id in list
            new_reconnection_id = self.update_connection(reconnection_id)

            print(self.open_connections)

            if self.auth_reconnection_set(client_reconnection_set):


                    print()
                    print("Client was successfully reconnected...")
                    print()

                    #put ids in list which have been already set
                    self.client_already_registered.append(new_reconnection_id)

                    client_reconnected = self.aes_client_encoding(new_reconnection_id.encode("utf-8"))
                    client_socket.send(client_reconnected)

                    enc_client_host_port_dict = client_socket.recv(2048)
                    enc_client_host_port_dict = self.aes_client_decoding(enc_client_host_port_dict)

                    client_host_port_dict = pickle.loads(enc_client_host_port_dict)

                    #update dict with client reconnection id
                    client_host_port_dict["client_reconnection_id"] = new_reconnection_id

                    self.client_host_port_dict = client_host_port_dict

                    self.client_host_port_dict_list.append(self.client_host_port_dict)

                    client_host_port = self.aes_client_encoding(b"GATEWAY_RECEIVED_CLIENT_HOST_PORT")
                    client_socket.send(client_host_port)

                    client_action_request = client_socket.recv(2048)
                    client_action_request = self.aes_client_decoding(client_action_request)

                    if client_action_request == b"CLIENT_WILL_SEND_MODEL_WEIGHTS":

                        #calling function to get client model weights
                        print()
                        print("Receiving Client Model Weights")
                        print()

                        self.get_client_model_weights(client_socket)

            else:

                print("Client cannot reconnect!")


    def handle_client(self, client_socket, client_address):

        client_socket.send(b"OPEN_THREAD")

        print("Started Thread")

        gateway_input = client_socket.recv(2048)

        if gateway_input == b"SERVER_READY_FOR_RSA" or gateway_input == b"CLIENT_READY_FOR_RSA":

            client_socket.send(b"GATEWAY_READY_FOR_RSA")

            tmpHash, clientPublicHash, client_public_key = self.verify_client_keys(client_socket)

            if tmpHash == clientPublicHash:
                
                self.send_gateway_keys(client_socket, client_address, client_public_key)
              
            else:

                print("Client not able to connect")
                self.server_busy = False
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.run_server()


        elif gateway_input != b"SERVER_READY_FOR_RSA" or gateway_input != b"CLIENT_READY_FOR_RSA":

            with self.lock:

                reconnection_id = gateway_input.decode("utf-8")

                if reconnection_id in self.open_connections:

                    if reconnection_id not in self.client_already_registered:

                        print("Reconnection Id: ", reconnection_id)

                        client_socket.send(b"GATEWAY_READY_FOR_RSA")

                        #set up aes again
                        tmpHash, clientPublicHash, client_public_key = self.verify_client_keys(client_socket)

                        if tmpHash == clientPublicHash:

                            #send the public key of gateway again to the client
                            client_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

                            client_return_aes_verify = client_socket.recv(4096)

                            if client_return_aes_verify == b"GATEWAY_KEYS_VERIFIED_BY_CLIENT":

                                fSendEncClient = self.set_aes_client_encryption(client_public_key)

                                client_socket.send(bytes(fSendEncClient + self.delimiter_bytes + self.public))

                                clientPH = client_socket.recv(4096)

                                if clientPH:
                                
                                    private_key = RSA.import_key(self.private)
                                    cipher = PKCS1_OAEP.new(private_key)
                                    decrypted_data_client = cipher.decrypt(clientPH)

                                    if decrypted_data_client == self.eightByteClient:
                                    
                                        encrypted_data = self.aes_client_encoding(b"AES_READY_CLIENT")
                                        client_socket.send(encrypted_data)

                                        aes_setup = client_socket.recv(4096)
                                        aes_setup = self.aes_client_decoding(aes_setup)

                                        if aes_setup == b"AES_VERIFIED_CLIENT":

                                            self.test_client_connection(client_socket, reconnection_id)

                        else:
                            print("Public Key from Client not verified")

                    elif reconnection_id in self.client_already_registered:
                    
                        client_socket.send(b"CLIENT_WAIT")

                        print(reconnection_id, "Client already connected")
                        client_socket.close()

                        time.sleep(3)
                        self.server_busy = False
                        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.run_server()

                else:

                    print()
                    print("Client passed wrong client reconnection id")
                    print()


    #get request from client
    def get_participant_request(self):

        print("***********************************************************")
        print()
        print("Gateway-Server is ready for connection...")
        print()
        print("***********************************************************")

        if len(self.open_connections) > 0:
            print(f"{len(self.open_connections)} running Connections")

        for connection in self.open_connections:
            print("Open Connection ID: ", connection)

        print()
        print("Server is open...")
        print()

        if not self.server_busy:

            client_socket, client_address = self.server_socket.accept()
            self.server_busy = True

            print()
            print("Server is busy...")
            print()

            print()
            print(f"Connection with {client_address}")
            print()

             # Mehrere Clients handhaben
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()
            
        elif self.server_busy:

            print("Server is busy")

            self.get_participant_request()


    #client sends its public key and it´s hashed. Here it gets checked
    def verify_client_keys(self, client_socket):
        
        clientPH = client_socket.recv(4096)

        if clientPH:

            try:

                split = clientPH.split(self.delimiter_bytes)

                clientPublicKey = split[0].decode('utf-8')
                clientPublicKeyHash = split[1].decode('utf-8')

                cleanedClientPublicKey = clientPublicKey.replace("\r\n", '')
                cleanedClientPublicKeyHash = clientPublicKeyHash.replace("\r\n", '')

                tmpClientPublic_bytes = cleanedClientPublicKey.encode('utf-8')

                tmpHashObject = hashlib.sha3_256(tmpClientPublic_bytes)
                tmpHash = tmpHashObject.hexdigest()

                return tmpHash, cleanedClientPublicKeyHash, clientPublicKey
            
            except:

                print("Client was not able to have stable connection")
                self.get_participant_request()
        
        else:
            print("Client closed connection")
            self.get_participant_request()
    

    #if client or server keys are verified, gateway sends his keys back
    def send_gateway_keys(self, client_socket, client_address, client_public_key):

        client_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

        self.get_participant_data(client_socket, client_address, client_public_key)

    
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
    

    #get data from client
    def get_participant_data(self, client_socket, client_address, client_public_key):
        
        data = client_socket.recv(1024)

        #if server accepted than...
        if data == b"GATEWAY_KEYS_VERIFIED_BY_SERVER":

            #set up aes encryption with aggregate server
            fSendEnc = self.set_aes_encryption(client_public_key)
            client_socket.send(bytes(fSendEnc + self.delimiter_bytes + self.public))

            serverPH = client_socket.recv(4096)
    
            if serverPH:

                private_key = RSA.import_key(self.private)
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_data = cipher.decrypt(serverPH)

                #if shared secret which got sent to client and got sent back properly aes is getting prepared
                if decrypted_data == self.eightByte:
                
                    encrypted_data = self.aes_encoding(b"AES_READY")
                    client_socket.send(encrypted_data)

                    aes_setup = client_socket.recv(4096)
                    aes_setup = self.aes_decoding(aes_setup)

                    if aes_setup == b"AES_VERIFIED":

                        get_url = self.aes_encoding(b"GET_CONNECTION_URL")
                        client_socket.send(get_url)

                        formatted_client_address = client_socket.recv(2048)
                        formatted_client_address = self.aes_decoding(formatted_client_address)
                        formatted_client_address = formatted_client_address.decode("utf-8")

                        print(f"Server on {formatted_client_address} gets his smart contract...")

# Server soll Kaution noch übermitteln!!!!                        
                        
                        # Server zur Client-Liste hinzufügen
                        self.connected_server_nodes.append(formatted_client_address)
                        server_reconnection_id = self.register_connection()

                        server_smart_contract_data = SmartContract(role="AggregateServer",
                                       participant_public_key=client_public_key).set_up_account(self.gateway_smart_contract,
                                                                                                 formatted_client_address)

                        aggregate_server_contract, server_smart_contract_dict = SmartContract(role="Gateway",
                                                        participant_public_key=client_public_key).open_contract(
                                                        contract_path="Test.sol",
                                                        contract_name="ServerSetUp"
                                                        )

                        
                         #deployed aggregate Server smart contract, just for the aggregate server
                        self.aggregate_server_smart_contract = server_smart_contract_dict

                        print()
                        print("Aggregate Server Contract Deployed: ", aggregate_server_contract.address)
                        print()

                        #collect all registered servers in the BC
                        self.server_account_addresses.append(server_smart_contract_data['AccountAddress'])
                        self.connected_server.add(client_socket)

                        ### Verify Aggregate-Server ###

                        # Build up smart contract for server and add account to BC
                        accept_msg = self.aes_encoding(b"SERVER_ACCEPTED_FROM_GATEWAY")
                        client_socket.send(accept_msg)

                        server_ready_flag = client_socket.recv(1024)
                        server_ready_flag = self.aes_decoding(server_ready_flag)

                        if server_ready_flag == b"READY_SMART_CONTRACT":
                            
                            #gateway is sending server smart contract data
                            smart_contract_data = pickle.dumps(server_smart_contract_data)
                            smart_contract_data_bytes = self.aes_encoding(smart_contract_data)
                            client_socket.send(smart_contract_data_bytes)

                            received_server_smart_contract = client_socket.recv(1024)
                            received_server_smart_contract = self.aes_decoding(received_server_smart_contract)

                            if received_server_smart_contract == b"RECEIVED_SMART_CONTRACT_DATA":

                                server_reconnection_id = self.aes_encoding(server_reconnection_id.encode("utf-8"))
                                client_socket.send(server_reconnection_id)

                                self.get_global_model(client_socket, client_public_key, server_smart_contract_data)

########### CLIENT ############

        #client gets device key, encrypted model from bc, modelhash and smart contract, list of registered servers
        elif data == b"GATEWAY_KEYS_VERIFIED_BY_CLIENT":

            #set up aes encryption with aggregate server
            fSendEncClient = self.set_aes_client_encryption(client_public_key)
            client_socket.send(bytes(fSendEncClient + self.delimiter_bytes + self.public))

            clientPH = client_socket.recv(4096)

            if clientPH:

                private_key = RSA.import_key(self.private)
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_data_client = cipher.decrypt(clientPH)

                #if shared secret which got sent to client and got sent back properly aes is getting prepared
                if decrypted_data_client == self.eightByteClient:
                
                    encrypted_data = self.aes_client_encoding(b"AES_READY_CLIENT")
                    client_socket.send(encrypted_data)

                    aes_setup = client_socket.recv(4096)
                    aes_setup = self.aes_client_decoding(aes_setup)

                    if aes_setup == b"AES_VERIFIED_CLIENT":

                        self.connected_client_nodes.append(client_address)
                        client_reconnection_id = self.register_connection()

                        #instead if client PK there is build a new device key
                        client_smart_contract_data = SmartContract(role="Client",
                                participant_public_key=build_device_key()).set_up_account(smart_contract=self.gateway_smart_contract,
                                                                                      connection_url="")

                        set_smart_contract_client = self.aes_client_encoding(b"SET_CLIENT_SMART_CONTRAT")
                        client_socket.send(set_smart_contract_client)

                        client_ready_flag = client_socket.recv(1024)
                        client_ready_flag = self.aes_client_decoding(client_ready_flag)

                        if client_ready_flag == b"READY_SMART_CONTRACT":
                        
                            client_smart_contract_data_bytes = pickle.dumps(client_smart_contract_data)
                            client_smart_contract_data = self.aes_client_encoding(client_smart_contract_data_bytes)
                            client_socket.send(client_smart_contract_data)

                            client_got_smart_contract = client_socket.recv(1024)
                            client_got_smart_contract = self.aes_client_decoding(client_got_smart_contract)
                                
                            if client_got_smart_contract == b"RECEIVED_SMART_CONTRACT":
                                    
                                    serialized_gateway_smart_contract_client = pickle.dumps(self.gateway_contract_dict)
                                    serialized_gateway_smart_contract_client = self.aes_client_encoding(serialized_gateway_smart_contract_client)
                                    client_socket.send(serialized_gateway_smart_contract_client)

                                    wait_reconnection_id = client_socket.recv(1024)
                                    wait_reconnection_id = self.aes_client_decoding(wait_reconnection_id)

                                    if wait_reconnection_id == b"WAIT_FOR_RECON_ID":
                                    
                                        enc_client_reconnection_id = self.aes_client_encoding(client_reconnection_id.encode("utf-8"))
                                        client_socket.send(enc_client_reconnection_id)

                                        got_reconnection_id = client_socket.recv(1024)
                                        got_reconnection_id  = self.aes_client_decoding(got_reconnection_id)
                                    
                                        #sending possible server to connect
                                        if len(self.server_account_addresses) > 0 and got_reconnection_id == b"GOT_RECONNECTION_ID":
                                            server_addresses = json.dumps(self.server_account_addresses)
                                            server_addresses_bytes = server_addresses.encode('utf-8')
                                            server_addresses = self.aes_client_encoding(server_addresses_bytes)
                                            client_socket.send(server_addresses)

                                        else:
                                            not_server_addresses = self.aes_client_encoding(b"NO_SERVER_AVAILABLE")
                                            client_socket.send(not_server_addresses)
                                            self.server_busy = False
                                            self.get_participant_request()

                                        selected_server = client_socket.recv(1024)
                                        selected_server = self.aes_client_decoding(selected_server)

                                        server_smart_contract_data = SmartContract(role="Gateway",
                                                participant_public_key=self.public).get_aggregate_server(
                                                                                        selected_server.decode("utf-8"),
                                                                                        self.gateway_smart_contract)

                                        server_smart_contract_data_bytes = encode_dict(server_smart_contract_data)
                                        server_smart_contract_data = self.aes_client_encoding(server_smart_contract_data_bytes)
                                        client_socket.send(server_smart_contract_data)

                                        ready_gateway_model = client_socket.recv(1024)
                                        ready_gateway_model = self.aes_client_decoding(ready_gateway_model)

                                        if ready_gateway_model == b"READY_GATEWAY_MODEL":

                                            if self.encrypted_model is not None:

                                                if isinstance(self.encrypted_model, bytes):

                                                    encrypted_model = self.aes_client_encoding(self.encrypted_model)
                                                    client_socket.sendall(encrypted_model)

                                                else:
                                                    self.encrypted_model = self.encrypted_model.encode("utf-8")
                                                    encrypted_model = self.aes_client_encoding(self.encrypted_model)
                                                    client_socket.sendall(encrypted_model)

                                                print("Sending enc model to client...")

                                                client_received_gateway_model = client_socket.recv(1024)
                                                client_received_gateway_model = self.aes_client_decoding(client_received_gateway_model)

                                                if client_received_gateway_model == b"RECEIVED_GATEWAY_MODEL":

                                                    client_reconnection_code = self.register_connection()

                                                    client_reconnection_set = {client_reconnection_id, client_reconnection_code}
                                                    pickled_client_reconnection_set = pickle.dumps(client_reconnection_set)

                                                    self.client_reconnection_sets.append(client_reconnection_set)

                                                    send_client_reconnection_set = self.aes_client_encoding(pickled_client_reconnection_set)
                                                    client_socket.send(send_client_reconnection_set)

                                                    #jumping to open connection
                                                    self.server_busy = False
                                                    self.get_participant_request()

                                        else:
                                            print("Client closed connection")
                                            self.server_busy = False
                                            self.get_participant_request()
                            else:
                                print("Client closed connection")
                                self.server_busy = False
                                self.get_participant_request()
                        else:
                            print("Client closed connection")
                            self.server_busy = False
                            self.get_participant_request()
                    else:
                            print("Client closed connection")
                            self.server_busy = False
                            self.get_participant_request()
            else:
                print("Client closed connection")
                self.server_busy = False
                self.get_participant_request()
        else:
            print("Client closed connection")
            self.server_busy = False
            self.get_participant_request()

    #get global model from aggregate-server
    #first encrypted model data
    #than with pk encrypted key to encrypt the encrypted model data
    def get_global_model(self, client_socket, client_public_key, server_smart_contract_data):

        
        #gateway gets encrypted model and hash
        #gets encryption key to encryp model and hash dict
        enc_encrypt_key = client_socket.recv(4096)
        enc_encrypt_key = self.aes_decoding(enc_encrypt_key)
        decrypt_dict_key = self.decrypt_encryption_key(enc_encrypt_key)
        
        got_key = self.aes_encoding(b"GOT_ENC_ENCRYPTION_KEY")
        client_socket.send(got_key)

        encrypted_model_hash_dict = client_socket.recv(65536)
        encrypted_model_hash_dict = self.aes_decoding(encrypted_model_hash_dict)

        got_model_dict = self.aes_encoding(b"GOT_ENC_MODEL_DATA")
        client_socket.send(got_model_dict)

        #gateway encrypts model data
        decrypted_enc_model_data_bytes = self.decrypt_enc_model_data(decrypt_dict_key, encrypted_model_hash_dict)
        decrypted_enc_model_data = decode_dict(decrypted_enc_model_data_bytes)

        #this is getting saved in the BC, the enc model and the model hash
        self.encrypted_model = decrypted_enc_model_data["EncryptedModel"]
        model_hash = decrypted_enc_model_data["ModelHash"]

        #save model in BC
        #hash the encrypted to save space on BC save hash or full model?
        encrypted_model_hash = self.hash_model(self.encrypted_model)

        ready_smart_contract = client_socket.recv(4096)
        ready_smart_contract = self.aes_decoding(ready_smart_contract)

        if ready_smart_contract == b"GET_SMART_CONTRACT":

                serialized_gateway_smart_contract = pickle.dumps(self.gateway_contract_dict)
                serialized_gateway_smart_contract = self.aes_encoding(serialized_gateway_smart_contract)
                client_socket.send(serialized_gateway_smart_contract)

                received_gateway_smart_contract = client_socket.recv(4096)
                received_gateway_smart_contract = self.aes_decoding(received_gateway_smart_contract)

                if received_gateway_smart_contract == b"RECEIVED_BASE_SMART_CONTRACT":

                    #jumping to client
                    self.server_busy = False
                    self.get_participant_request()


    def transform_smart_contract(self, smart_contract):

        contract_info = {
            'address': smart_contract.address,
            'abi': smart_contract.abi
        }

        contract_info_json = pickle.dumps(contract_info)

        return contract_info_json


    def decrypt_encryption_key(self, enc_encrypt_key):
        
        key = RSA.importKey(self.private)
        cipher = PKCS1_OAEP.new(key)
        decrypted_key = cipher.decrypt(enc_encrypt_key)

        return decrypted_key
         

    def decrypt_enc_model_data(self, decrypt_dict_key, enc_model_data):

        cipher = Fernet(decrypt_dict_key)
        decrypted_enc_model_data = cipher.decrypt(enc_model_data)
        return decrypted_enc_model_data


    def hash_model(self, global_model):
        
        hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8')).hexdigest()

        return hashed_global_model
    

    #get the model weights of the client
    def get_client_model_weights(self, client_socket):

        ready_for_model_weights = self.aes_client_encoding(b"GATEWAY_READY_FOR_MODEL_WEIGHTS")
        client_socket.send(ready_for_model_weights)
        
        dec_client_model_weights = client_socket.recv(65536)
        dec_client_model_weights = self.aes_client_decoding(dec_client_model_weights)

        final_client_model_weights = pickle.loads(dec_client_model_weights)

        client_device_key = final_client_model_weights["DeviceKey"]
        client_model_weights = final_client_model_weights["ModelWeights"]

        self.verify_client_model_weights(client_socket, client_device_key, client_model_weights, dec_client_model_weights)


    #checks if client really exists in BC and if model weights has changed
    def verify_client_model_weights(self, client_socket, client_device_key, client_model_weights, dec_client_model_weights):

        print()
        print("Gateway is verifing client model weights")
        print()
        
        client_smart_contract_model_weights= SmartContract(role="Gateway",
                participant_public_key=self.public).get_client_model_weights(client_device_key, self.gateway_smart_contract)

        hashed_client_model_weights = self.hash_model(client_model_weights)

        if str(client_smart_contract_model_weights["ModelWeightsHash"]) == str(hashed_client_model_weights):

            print()
            print("Modelweights were not changed")
            print()
            print("Client Smart Contract: ", client_smart_contract_model_weights)
            print()

            client_model_weights_received = self.aes_client_encoding(b"CLIENT_MODEL_WEIGHTS_RECEIVED")
            client_socket.send(client_model_weights_received)

            self.received_connection_weights += 1

            print("Received Connection Weights: ", self.received_connection_weights)
            print("Required Connection Weights: ", self.required_client_weights)

            client_socket.close()

            if self.received_connection_weights >= self.required_client_weights:

                print()
                print("Connecting to aggregate server, sending client model weights...")
                print()

                #connect to aggregate server if enough model weights were collected!
                self.received_connection_weights = 0
                self.connect_aggregate_server(dec_client_model_weights)

            else:

                print()
                print("Waiting for more client model weights")
                print()

                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.run_server()

        else:
            print("Modelweights of Client were changed. Stop transmitting.")


    #how to select server
    #after receiving an amount of model weights the gateway server selects the aggregate server to send him the model weights
    def connect_aggregate_server(self, dec_client_model_weights):

            self.server_socket.close()
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            selected_server = self.connected_server_nodes[0]
            host, port = selected_server.split(':')

            self.server_socket.connect((str(host), int(port)))

            print(f"Connected to Aggregate-Server {host}:{port}")

            self.server_socket.send(b"GATEWAY_READY_FOR_RECONNECTION")

            server_connection_test = self.server_socket.recv(4096)
            server_connection_test = self.aes_decoding(server_connection_test)

            server_connection_test_hash = self.hash_model(server_connection_test)
  
            server_connection_test_hash = self.aes_encoding(server_connection_test_hash.encode("utf-8"))
            self.server_socket.send(server_connection_test_hash)

            server_waiting_model_weights = self.server_socket.recv(1024)
            server_waiting_model_weights = self.aes_decoding(server_waiting_model_weights)
            
            if server_waiting_model_weights == b"SERVER_WAITING_MODEL_WEIGHTS":
                
                enc_client_model_weights = self.aes_encoding(dec_client_model_weights)
                self.server_socket.send(enc_client_model_weights)

                print()
                print("Sending encrypted model weights to Server....")
                print()

                self.get_updated_model_weights()


    #getting updated model weights from aggregate server
    def get_updated_model_weights(self):

        enc_client_model_weights = self.server_socket.recv(65536)

        server_global_model_weights = self.aes_decoding(enc_client_model_weights)
        self.server_global_model_weights = server_global_model_weights

        server_global_model_weights_dict = pickle.loads(server_global_model_weights)

        server_account_address = server_global_model_weights_dict["ServerAccountAddress"]
        server_model_weights = server_global_model_weights_dict["ServerModelWeights"]

        server_waiting_model_weights_hash = self.hash_model(server_model_weights)

        #verify receiving model_weights
        if self.verify_server_model_weights(server_account_address, server_waiting_model_weights_hash):
            
            received_server_model_weights = self.aes_encoding(b"GATEWAY_RECEIVED_SERVER_MODEL_WEIGHTS")
            self.server_socket.send(received_server_model_weights)

            restart_training_round = self.server_socket.recv(1024)
            restart_training_round = self.aes_decoding(restart_training_round)

            if restart_training_round == b"TRAINING_FINISHED":
                
                print()
                print("Training finished by Server... Last sending to client")
                print()

                print(self.client_host_port_dict_list)

                #now gateway connects to the client and sends them the finished weights!
                for index, client in enumerate(self.client_host_port_dict_list):

                    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    client_server_host = client['host']
                    client_server_port = client['port']

                    self.server_socket.connect((client_server_host, client_server_port))

                    self.server_socket.send(b"GATEWAY_SEND_UPDATED_MODEL_WEIGHTS_FINAL")

                    client_action_request = self.server_socket.recv(1024)

                    if client_action_request == b"CLIENT_WAITING_FOR_MODEL_WEIGHTS_UPDATE":

                        print()
                        print("Sending updated Model weights to client", client)
                        print()

                        if index == len(self.client_host_port_dict_list) - 1:

                            self.last_client = True

                        self.send_updated_model_weights_to_client(self.server_socket)


                self.client_host_port_dict_list = []

            elif restart_training_round == b"SERVER_INIT_NEXT_TRAINING_ROUND":
                
                print()
                print("Init next training round")
                print()

                self.client_already_registered = []

                self.server_socket.close()
                
                print(self.client_host_port_dict_list)

                #now gateway connects to the client and sends them the finished weights!
                for index, client in enumerate(self.client_host_port_dict_list):

                    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    client_server_host = client['host']
                    client_server_port = client['port']

                    self.server_socket.connect((client_server_host, client_server_port))

                    self.server_socket.send(b"GATEWAY_SEND_UPDATED_MODEL_WEIGHTS")

                    client_action_request = self.server_socket.recv(1024)

                    if client_action_request == b"CLIENT_WAITING_FOR_MODEL_WEIGHTS_UPDATE":

                        print()
                        print("Sending updated Model weights to client: ", client)
                        print()

                        if index == len(self.client_host_port_dict_list) - 1:

                            self.last_client = True

                        self.send_updated_model_weights_to_client(self.server_socket)

                self.client_host_port_dict_list = []

            #all done than jump back in open server connection
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.run_server()
            

    #checks if client really exists in BC and if model weights has changed
    def verify_server_model_weights(self, server_account_address, server_waiting_model_weights_hash):
        
        server_smart_contract_model_weights = SmartContract(role="Gateway",
                participant_public_key=self.public).get_server_model_weights_hash(server_account_address,
                                                                                   self.gateway_smart_contract)
        
        print("Server Smart Contract", server_smart_contract_model_weights)

        if str(server_smart_contract_model_weights["ServerModelWeightsHash"]) == str(server_waiting_model_weights_hash):

            print()
            print("Gateway verified. Global Model Weights from Server were not changed")
            print()
            return True


    #reconnect with clients to send the updated model weights
    def send_updated_model_weights_to_client(self, server_socket):

#muss wieder aes verschlüsselt sein!

        server_socket.send(self.server_global_model_weights)
        server_socket.close()

        print()
        print("Updated Model weights were sent to the client")
        print()
        
        #reset the socket to reopen the gateway again for every connection
        self.server_busy = False

        #if last client than set server models to none
        if self.last_client:
            
            self.server_global_model_weights = None
            self.last_client = False



    #close server and client connection
    def close_connection(self):
        self.server_socket.close()
        print("Server Connection closed")
        for client_socket in self.connected_clients:
                client_socket.close()


if __name__ == "__main__":

    server = Server()
    server.run_server()