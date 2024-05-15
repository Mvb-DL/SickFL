from web3 import Web3


class ServerSmartContract():

    def __init__(self):

        self.w3 = Web3(Web3.HTTPProvider("http://localhost:7545"))

        self.contract_address = None
        self.smart_contract_data = None


    ###### Save Global Model in BC ######
    def set_up_global_model(self, enc_model, enc_model_hash, account_address, server_smart_contract):

        allowed_account_address = self.w3.to_checksum_address(account_address)

        tx_hash = server_smart_contract.functions.setModel(allowed_account_address,
                                                            enc_model,
                                                            enc_model_hash).transact({
                                                                            'from': allowed_account_address
                                                                            })

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        print("Model has been set successfully by Server!")

        return True
    

    ####### Save aggregated Model Weights of all Clients in BC #########
    #gets called by server
    def set_aggregated_model_weights(self, aggregated_model_weights_hash, account_address, smart_contract):

        tx_hash = smart_contract.functions.setGlobalModelWeights(account_address, aggregated_model_weights_hash).transact(({'from': account_address}))

        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        print("Global Model Weights has been set successfully by Server!")

        smart_contract_data = self.get_aggregate_server(account_address, smart_contract)

        return smart_contract_data
    

    #gets called by server
    #get the smart contract of the client by passing his client device key which is the account id for the server
    def get_client_model_weights_server(self, client_device_key, account_address, smart_contract):

        account_id, account_address, account_role, account_model_weights_hash = smart_contract.functions.getClientModelWeights(client_device_key).call({'from': account_address})

        client_smart_contract = {
                                'AccountId': f"{account_id}",
                                'AccountAddress': f'{account_address}',
                                'Role': f'{account_role}',
                                "ModelWeightsHash": f"{account_model_weights_hash}"
                                }

        return client_smart_contract
    

    def get_aggregate_server(self, server_account_address, smart_contract):

        account_id, account_address, account_role, connection_url, enc_model, model_hash, global_model_weights = smart_contract.functions.getAggregateServer(server_account_address).call()

        if account_address == server_account_address:

            server_smart_contract_data = { 'AccountId': f"{account_id}",
                                    'AccountAddress': f'{account_address}',
                                    'Role': f'{account_role}',
                                    "ConnectionUrl": f"{connection_url}",
                                    "EncModel": f"{enc_model}",
                                    "ModelHash": f"{model_hash}",
                                    "GlobalModelWeights":  f"{global_model_weights}"
                                }
                                
            
            return server_smart_contract_data

        else:
            print("Account does not exist!")
            return False
        

    def get_client_by_public_key(self, client_public_key, smart_contract):

            verify_client = smart_contract.functions.verifyClient(client_public_key).call()

            return verify_client

    
    def rebuild_smart_contract(self, server_smart_contract_dict):

        reconstructed_contract = self.w3.eth.contract(
            address=server_smart_contract_dict['ContractAdress'],
            abi=server_smart_contract_dict['Abi']
        )

        return reconstructed_contract
    