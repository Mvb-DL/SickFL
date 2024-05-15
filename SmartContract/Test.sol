// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GatewaySetUp{

    struct Gateway {
        string gatewayId;
        address accountAddress;
        uint256 depositAmount;
        string role;
        string connectionUrl;
        bool isExist;
    }

    struct AggregateServer {
        string serverId;
        address accountAddress;
        uint256 depositAmount;
        string role;
        string connectionUrl;
        string encModelHash;
        string modelHash;
        string globalModelWeightsHash;
        bool isExist;
    }

    struct Client {
        string clientId;
        address accountAddress;
        uint256 depositAmount;
        string role;
        string localModelWeightsHash;
        bool isExist;
    }

    address owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyGateway {
        require(msg.sender == owner, "Caller is not Gateway");
        _;
    }

    mapping (address=>Gateway) gateways;
    mapping (address=>AggregateServer) public servers;
    mapping (address=>Client) clients;

    //restrictions for child contracts
    mapping (address => bool) allowedServerAddresses;
    mapping (address => bool) allowedClientAddresses;


    mapping(string => bool) public clientExistsByPk;

    event GatewayRegistered(string gatewayId, address indexed accountAddress, uint256 depositAmount, string connectionUrl);

    function registerGateway(string memory _gatewayId, address _accountAddress, uint256 _depositAmount, 
                                string memory _connectionUrl) public onlyGateway payable {

        require(gateways[_accountAddress].isExist==false, "Gateway with this ID already exists");
        require(msg.value == 0.1 ether, "Deposit amount must be 0.1 ether");

        gateways[_accountAddress] = Gateway({
            gatewayId: _gatewayId,
            accountAddress: _accountAddress,
            depositAmount: _depositAmount,
            role: "Gateway",
            connectionUrl: _connectionUrl,
            isExist: true
        });

        emit GatewayRegistered(_gatewayId, _accountAddress, _depositAmount,  _connectionUrl);
    }

    function getGateway(address _accountAddress) public view returns (string memory, address, string memory, string memory) {
        return (gateways[_accountAddress].gatewayId, gateways[_accountAddress].accountAddress, gateways[_accountAddress].role, gateways[_accountAddress].connectionUrl);
    }


    event AggregateServerRegistered(string serverId, address indexed accountAddress, uint256 depositAmount, string connectionUrl);

    function registerAggregateServer(string memory _serverId, address _accountAddress, uint256 _depositAmount,
                                     string memory _connectionUrl) public onlyGateway payable {

        require(servers[_accountAddress].isExist==false, "Server with this ID already exists");
        require(msg.value == 0.1 ether, "Deposit amount must be 0.1 ether");

        servers[_accountAddress] = AggregateServer({
            serverId: _serverId,
            accountAddress: _accountAddress,
            depositAmount: _depositAmount,
            role: "AggregateServer",
            connectionUrl: _connectionUrl,
            encModelHash: "",
            modelHash: "",
            globalModelWeightsHash: "",
            isExist: true
        });

        emit AggregateServerRegistered(_serverId, _accountAddress, _depositAmount,  _connectionUrl);
    }

    function getAggregateServer(address _accountAddress) public view returns (string memory,
                            address, string memory, string memory, string memory, string memory, string memory) {

        return (servers[_accountAddress].serverId, servers[_accountAddress].accountAddress, servers[_accountAddress].role,
                servers[_accountAddress].connectionUrl, servers[_accountAddress].encModelHash, servers[_accountAddress].modelHash,
                servers[_accountAddress].globalModelWeightsHash);
    }


    event ClientRegistered(string clientId, address indexed accountAddress, uint256 depositAmount);

    function registerClient(string memory _clientId, address _accountAddress, uint256 _depositAmount) public onlyGateway payable {

        require(clients[_accountAddress].isExist==false, "Client with this ID already exists");
        require(msg.value == 0.1 ether, "Deposit amount must be 0.1 ether");

        clients[_accountAddress] = Client({
            clientId: _clientId,
            accountAddress: _accountAddress,
            depositAmount: _depositAmount,
            role: "Client",
            localModelWeightsHash: "",
            isExist: true
        });

        clientExistsByPk[_clientId] = true;

        emit ClientRegistered(_clientId, _accountAddress, _depositAmount);
    }

    function getClient(address _accountAddress) public view returns (string memory, address, string memory, string memory) {

        return (clients[_accountAddress].clientId, clients[_accountAddress].accountAddress,
                 clients[_accountAddress].role, clients[_accountAddress].localModelWeightsHash);
    }

    modifier onlyAggregateServer() {
        require(allowedServerAddresses[msg.sender], "Caller is not allowed to access this function");
        _;
    }

    function allowServerAddress(address _address) public {
        allowedServerAddresses[_address] = true;
    }

    event ModelSet(address indexed accountAddress, string encModel, string modelHash);

    function setModel(address _accountAddress, string memory _enc_model, string memory _hash) public onlyAggregateServer {

        AggregateServer storage server = servers[_accountAddress];
        require(servers[_accountAddress].isExist==true, "Server does not exist!");

        server.encModelHash = _enc_model;
        server.modelHash = _hash;

        emit ModelSet(_accountAddress, _enc_model, _hash);
    }


    modifier onlyClient() {
        require(allowedClientAddresses[msg.sender], "Caller is not allowed to access this function");
        _;
    }

    function allowClientAddress(address _address) public {
        allowedClientAddresses[_address] = true;
    }

    event GlobalModelWeightsSet(address indexed accountAddress, string globalModelWeigthsHash);

    function setGlobalModelWeights(address _accountAddress, string memory _global_model_weights) public onlyAggregateServer {

        AggregateServer storage server = servers[_accountAddress];
        require(servers[_accountAddress].isExist==true, "Server does not exist!");

        server.globalModelWeightsHash = _global_model_weights;

        emit GlobalModelWeightsSet(_accountAddress, _global_model_weights);
    }
    

    event LocalModelWeightsSet(address indexed accountAddress, string modelWeightsHash);

    function setClientModelWeights(address _accountAddress, string memory _client_model_weights) public onlyClient  {

        Client storage client = clients[_accountAddress];
        require(clients[_accountAddress].isExist==true, "Client does not exist!");

        client.localModelWeightsHash = _client_model_weights;

        emit LocalModelWeightsSet(_accountAddress, _client_model_weights);
    }


    function getServerModelWeights(address _accountAddress) external view returns (string memory,
                                                                         address, string memory, string memory) {

        return (servers[_accountAddress].serverId, servers[_accountAddress].accountAddress,
         servers[_accountAddress].role, servers[_accountAddress].globalModelWeightsHash);
    }


    function getClientModelWeights(address _accountAddress) external view returns (string memory, address, string memory, string memory) {

        return (clients[_accountAddress].clientId, clients[_accountAddress].accountAddress,
         clients[_accountAddress].role, clients[_accountAddress].localModelWeightsHash);
    }

    //function which checks if client exists by passing client pk
    function verifyClient(string memory _id) external view returns (bool) {
        return clientExistsByPk[_id];
    } 
}


contract ServerSetUp is GatewaySetUp {
    
    function find_account(address _address) public view returns(string memory){      
      return servers[_address].serverId;
    }

}

