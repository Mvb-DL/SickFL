from SmartContract.smart_contract import SmartContract
from web3 import Web3

class ClientSmartContract():

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider("http://localhost:7545"))


    ####### Save Model Weights from Client in BC #######
    #gets called by client
    def set_client_model_weights(self, model_weights, account_address, smart_contract):

        tx_hash = smart_contract.functions.setClientModelWeights(account_address, model_weights).transact(({'from': account_address}))

        print("Model Weights has been set successfully by Client!")

        smart_contract_data = self.get_client(account_address, smart_contract)

        return smart_contract_data
    

    #get the server model data as client
    #gets called by client
    def get_server_model_weights_hash_client(self, server_account_address, account_address, smart_contract):

        account_id, account_address, account_role, server_model_weights_hash = smart_contract.functions.getServerModelWeights(server_account_address).call({'from': account_address})

        server_smart_contract = {
                                'AccountId': f"{account_id}",
                                'AccountAddress': f'{account_address}',
                                'Role': f'{account_role}',
                                "ServerModelWeightsHash": f"{server_model_weights_hash}"
                                }

        return server_smart_contract
    

    def get_client(self, client_account_address, smart_contract):

        account_id, account_address, account_role, client_model_weights_hash = smart_contract.functions.getClient(client_account_address).call({'from': client_account_address})

        if account_address == client_account_address:

            client_smart_contract_data = { 'AccountId': f"{account_id}",
                                    'AccountAddress': f'{account_address}',
                                    'Role': f'{account_role}',
                                    "ModelWeights": f"{client_model_weights_hash}"
                                }
                                
            return client_smart_contract_data

        else:
            print("Account does not exist!")
            return False
        
    
    def rebuild_smart_contract(self, client_smart_contract_dict):

        reconstructed_contract = self.w3.eth.contract(
            address=client_smart_contract_dict['ContractAdress'],
            abi=client_smart_contract_dict['Abi']
        )

        return reconstructed_contract