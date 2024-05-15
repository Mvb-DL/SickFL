// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./GatewaySmartContract.sol";
/*
contract ServerSetUp is GatewaySetUp {

    event ModelSet(address indexed accountAddress, string encModel, string modelHash);
    event GlobalModelWeightsSet(address indexed accountAddress, string globalModelWeigthsHash);

    function setModel(address _accountAddress, string memory _enc_model, string memory _hash) public {

        AggregateServer storage account = aggregateServersByAddress[_accountAddress];
        account.encModelHash = _enc_model;
        account.modelHash = _hash;

        emit ModelSet(_accountAddress, _enc_model, _hash);
    }

    function setGlobalModelWeights(address _accountAddress, string memory _global_model_weights) public {

        AggregateServer storage account = aggregateServersByAddress[_accountAddress];
        require(account.accountAddress != address(0), "Server does not exist");
        account.globalModelWeightsHash = _global_model_weights;

        emit GlobalModelWeightsSet(_accountAddress, _global_model_weights);
    }

}*/