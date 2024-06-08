#utils function for all
import json, pickle
import hashlib
from sklearn.utils import shuffle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import numpy as np
from keras.models import model_from_json
from commands.server_commands import commands


def get_command_value(command_key):
    return commands.get(command_key)


#hash the model
def hash_model(global_model):
        
    hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
    return hashed_global_model
    

def encode_dict(_dict):

    dict_json = json.dumps(_dict, ensure_ascii=False)
    dict_json_bytes = dict_json.encode("utf-8")

    return dict_json_bytes


def decode_dict(_dict_json_bytes):

    _dict_json = _dict_json_bytes.decode("utf-8")
    _dict = json.loads(_dict_json)

    return _dict


#gets modelhash and data hash from client before sending 
class ClientValidationContainer:

    def __init__(self, model_hash, client_data_hash, data_length_params, server_public_key):

        self.__model_hash = model_hash
        self.__client_data_hash = client_data_hash
        self.__data_length_params = data_length_params
        self.__server_public_key = server_public_key

    @property
    def model_hash(self):
        return self.__model_hash
    
    @property
    def client_data_hash(self):
        return self.__client_data_hash
    
    @property
    def data_length_params(self):
        return self.__data_length_params
    
    @property
    def server_public_key(self):
        return self.__server_public_key


    def verify_data(self, client_data_hash_by_client):

        if self.__client_data_hash == client_data_hash_by_client.encode("utf-8"):
            
            print("Datahash by Client and server are both same")
            return True
    
    def verify_model(self, client_model_hash_by_client):

        if str(self.__model_hash) == str(client_model_hash_by_client):

            print("Modelhash by Client and server are both same")
            return True
        

    #client gets the model from server and the datasize of the training data for the model
    def decapsulate_model(self, client_model_by_client, client_data_by_client, X_train, X_test, y_train, y_test):

        #hashes the model from client
        client_model_hash_by_client = hashlib.sha3_256(str(client_model_by_client).encode('utf-8')).hexdigest()

        #hash the data from client
        client_data_hash_by_client = hashlib.sha3_256(str(client_data_by_client).encode('utf-8')).hexdigest()

        if self.verify_data(client_data_hash_by_client):

            if self.verify_model(client_model_hash_by_client):
                
                    
                    #X_train = client_data_by_client[:X_train]
                    #X_test = client_data_by_client[X_train:X_train+X_test]
                    #y_train = client_data_by_client[X_train+X_test:X_train+X_test+y_train]
                    #y_test = client_data_by_client[X_train+X_test+y_train:]

                    b_server_datasize = self.__data_length_params
                    server_datasize = pickle.loads(b_server_datasize)

                    X_train, y_train = shuffle(X_train, y_train)
                    X_test, y_test = shuffle(X_test, y_test)

                    Server_X_train_len = server_datasize["X_train"]
                    Server_y_train_len = server_datasize["y_train"]
                    Server_X_test_len = server_datasize["X_test"]
                    Server_y_test_len = server_datasize["y_test"]

                    #reduce the data size of the client ml-model
                    overwritten_X_train = np.array(X_train[:int(Server_X_train_len)])
                    overwritten_y_train = np.array(y_train[:int(Server_y_train_len)])
                    overwritten_X_test = np.array(X_test[:int(Server_X_test_len)])
                    overwritten_y_test = np.array(y_test[:int(Server_y_test_len)])

                    print()
                    print("Overwritten Model Inputs: ", len(overwritten_X_train),
                                                        len(overwritten_y_train),
                                                        len(overwritten_X_test),
                                                        len(overwritten_y_test))
                    print()


                    model_architecture = model_from_json(client_model_by_client["model_architecture"])

                    model_architecture.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

                    model_architecture.fit(overwritten_X_train, overwritten_y_train, epochs=1, batch_size=32,
                                              validation_data=(overwritten_X_test, overwritten_y_test))

                    client_test_loss, client_test_accuracy = model_architecture.evaluate(overwritten_X_test, overwritten_y_test)

                    print()
                    print("Client Results of the example ML-Model:")
                    print()
                    print("Client Test Loss:", client_test_loss)
                    print("Client Test Accuracy:", client_test_accuracy)

                    client_model_test_validation = {
                                                    "ClientTestLoss": float(client_test_loss),
                                                    "ClientTestAccuracy": float(client_test_accuracy)
                                                }

                    pickled_client_model_test_validation = pickle.dumps(client_model_test_validation)

                    #result get´s encrypted automatically and just server can decrypt it!
                    rsa_key = RSA.import_key(self.__server_public_key)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                    encrypted_message = cipher_rsa.encrypt(pickled_client_model_test_validation)

                    return encrypted_message