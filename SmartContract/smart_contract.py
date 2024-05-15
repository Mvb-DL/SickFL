from web3 import Web3
from solcx import compile_standard
import solcx, random


class SmartContract:

    def __init__(self, role, participant_public_key):

        try:
            self.w3 = Web3(Web3.HTTPProvider("http://localhost:7545"))
        except:
            print("Ganache is not turned on!")
            
        self.gateway_account = self.w3.eth.accounts[0]

        self.server_account = None
        self.client_account = None

        self.contract_address = None
        self.role = role
        self.smart_contract_data = None
        self.participant_id = None

        if isinstance(participant_public_key, bytes):
            self.participant_id = participant_public_key.decode("utf-8")
        else:
            self.participant_id = participant_public_key


    #load solidity smart contract
    def open_contract(self, contract_path, contract_name):

        with open(f"./SmartContract/{contract_path}", "r") as file:
            contract_source_code = file.read()

        solcx.install_solc('0.8.0') 

        if contract_name == "GatewaySetUp":

            contract = self.compile_contract(
                                            contract_source_code=contract_source_code,
                                            contract_path=contract_path,
                                            contract_name=contract_name
                                        )
            
            return contract
            
        elif contract_name == "ServerSetUp":
            
            server_contract = self.compile_server_contract(
                                            contract_source_code=contract_source_code,
                                            contract_path=contract_path
                                        )

            return server_contract


    #compile the contract to use it in python
    def compile_contract(self, contract_source_code, contract_path, contract_name):

        compiled_sol = compile_standard(
            {
                "language": "Solidity",
                "sources": {f"{contract_path}": {"content": contract_source_code}},
                "settings": {
                    "outputSelection": {
                        "*": {
                            "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                        }
                    }
                }
            },
            solc_version="0.8.0",
        )

        #Gateway Contract
        gateway_contract_interface = compiled_sol["contracts"][f"{contract_path}"]["ServerSetUp"]
        bytecode = gateway_contract_interface["evm"]["bytecode"]["object"]
        abi = gateway_contract_interface["abi"]

        gateway_contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = gateway_contract.constructor().transact({'from': self.gateway_account})
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        gateway_contract = self.w3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=gateway_contract_interface['abi'],
        )

        gateway_smart_contract_dict = {
            "ContractAdress": tx_receipt.contractAddress,
            "Abi": abi
        }

        return gateway_contract, gateway_smart_contract_dict


    def compile_server_contract(self, contract_source_code, contract_path):

        compiled_sol = compile_standard(
            {
                "language": "Solidity",
                "sources": {f"{contract_path}": {"content": contract_source_code}},
                "settings": {
                    "outputSelection": {
                        "*": {
                            "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                        }
                    }
                }
            },
            solc_version="0.8.0",
        )

         #Aggregate Server Contract
        aggregate_server_contract_interface = compiled_sol["contracts"][f"{contract_path}"]["ServerSetUp"]
        bytecode = aggregate_server_contract_interface["evm"]["bytecode"]["object"]
        abi = aggregate_server_contract_interface["abi"]

        aggregate_server_contract = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = aggregate_server_contract.constructor().transact({'from': self.gateway_account})
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        aggregate_server_contract = self.w3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=aggregate_server_contract_interface['abi'],
        )

        server_smart_contract_dict = {
            "ContractAdress": tx_receipt.contractAddress,
            "Abi": abi
        }

        return aggregate_server_contract, server_smart_contract_dict 


    #build up the new account with its contract
    def generate_participant_address(self):

        rand_account_index = self.generate_unique_random()
        address = self.w3.eth.accounts[rand_account_index]

        return address
    

    def generate_unique_random(self):

        generated_numbers = set()

        while True:
            num = random.randint(0, 100)
            if num not in generated_numbers:
                generated_numbers.add(num)
                return num


    ###### Setting Up Account in BC ######
    
    def set_up_account(self, smart_contract, connection_url):
       
        deposit_amount = self.w3.to_wei(0.1, 'ether')

        #check which role the participant has...
        #server rols are passing a connection url
        if self.role == "Gateway":

            tx_hash = smart_contract.functions.registerGateway( self.participant_id,
                                                                    self.gateway_account,
                                                                    deposit_amount,
                                                                    connection_url).transact({'from': self.gateway_account,
                                                                                               'value': deposit_amount})
            
            self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
            gateway_smart_contract_data = self.get_gateway_server(self.gateway_account, smart_contract)

            return gateway_smart_contract_data


        elif self.role == "AggregateServer":

            self.server_account = self.generate_participant_address()

            tx_hash = smart_contract.functions.registerAggregateServer(self.participant_id,
                                                                        self.server_account,
                                                                        deposit_amount,
                                                                        connection_url).transact({
                                                                            'from': self.gateway_account,  
                                                                            'value': deposit_amount, 
                                                                            })
             
            self.w3.eth.wait_for_transaction_receipt(tx_hash)

            aggregate_server_smart_contract_data = self.get_aggregate_server(self.server_account, smart_contract)

            allow_account_address = self.w3.to_checksum_address(self.server_account)
            
            tx = smart_contract.functions.allowServerAddress(allow_account_address).transact({
                                                                            'from': self.gateway_account,  
                                                                            'value': 0, 
                                                                            })

            self.w3.eth.wait_for_transaction_receipt(tx)

            print()
            print(f"Server address {self.server_account} is registered and allowed to call contract ServerSetUp")
            print()

            return aggregate_server_smart_contract_data


        elif self.role == "Client":

            self.client_account = self.generate_participant_address()

            tx_hash = smart_contract.functions.registerClient(self.participant_id,
                                                                self.client_account,
                                                                deposit_amount).transact({
                                                                        'from': self.gateway_account,  
                                                                        'value': deposit_amount, 
                                                                            })
            
            self.w3.eth.wait_for_transaction_receipt(tx_hash)

            allow_client_account_address = self.w3.to_checksum_address(self.client_account)
            
            tx = smart_contract.functions.allowClientAddress(allow_client_account_address).transact({
                                                                            'from': self.gateway_account,  
                                                                            'value': 0, 
                                                                            })

            self.w3.eth.wait_for_transaction_receipt(tx)

            aggregate_server_smart_contract_data = self.get_client(self.client_account, smart_contract)

            print()
            print(f"Client address {allow_client_account_address} is registered and allowed to call contract ClientSetUp")
            print()

            return aggregate_server_smart_contract_data

        else:
            print("Role does not exist!")


    #for gateway
    def get_gateway_server(self, gateway_account_address, smart_contract):

        account_id, account_address, account_role, connection_url= smart_contract.functions.getGateway(gateway_account_address).call()

        if account_address == gateway_account_address:

            gateway_smart_contract_data = { 'AccountId': f"{account_id}",
                                            'AccountAddress': f'{account_address}',
                                            'Role': f'{account_role}',
                                            "ConnectionUrl": f"{connection_url}",
                                        }
                                
            return gateway_smart_contract_data

        else:
            print("Gateway does not exist!")
            return False

    #get the data of the aggregate server
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
            print("Aggregate Server does not exist!")
            return False
        
    #get client data
    def get_client(self, client_account_address, smart_contract):

        account_id, account_address, account_role, client_model_weights_hash = smart_contract.functions.getClient(client_account_address).call()

        if account_address == client_account_address:

            client_smart_contract_data = { 'AccountId': f"{account_id}",
                                    'AccountAddress': f'{account_address}',
                                    'Role': f'{account_role}',
                                    "ModelWeights": f"{client_model_weights_hash}"
                                }
                                
            return client_smart_contract_data

        else:
            print("Client does not exist!")
            return False

        
    #get the smart contract of the client by passing his client device key which is the account id
    def get_client_model_weights(self, client_device_key, smart_contract):
        
        account_id, account_address, account_role, account_model_weights_hash = smart_contract.functions.getClientModelWeights(client_device_key).call({'from': self.gateway_account})
        client_smart_contract = {
                                'AccountId': f"{account_id}",
                                'AccountAddress': f'{account_address}',
                                'Role': f'{account_role}',
                                "ModelWeightsHash": f"{account_model_weights_hash}"
                                }

        return client_smart_contract
    

    #get the smart contract of the client by passing his client device key which is the account id
    #gets called by gateway
    def get_server_model_weights_hash(self, server_account_address, smart_contract):

        account_id, account_address, account_role, server_model_weights_hash = smart_contract.functions.getServerModelWeights(server_account_address).call()

        server_smart_contract = {
                                'AccountId': f"{account_id}",
                                'AccountAddress': f'{account_address}',
                                'Role': f'{account_role}',
                                "ServerModelWeightsHash": f"{server_model_weights_hash}"
                                }

        return server_smart_contract
    

    

