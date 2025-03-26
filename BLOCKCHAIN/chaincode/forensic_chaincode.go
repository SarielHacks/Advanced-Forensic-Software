package main

import (
    "encoding/json" // Add this import
    "fmt"
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type ForensicChaincode struct {
    contractapi.Contract // Fix the typo here
}

type Evidence struct {
    ID        string `json:"id"`
    Action    string `json:"action"`
    Timestamp string `json:"timestamp"`
}

func (fc *ForensicChaincode) TrackCustody(ctx contractapi.TransactionContextInterface, id string, action string, timestamp string) error {
    evidence := Evidence{
        ID:        id,
        Action:    action,
        Timestamp: timestamp,
    }
    evidenceBytes, _ := json.Marshal(evidence)
    return ctx.GetStub().PutState(id, evidenceBytes)
}

func (fc *ForensicChaincode) QueryEvidence(ctx contractapi.TransactionContextInterface, id string) (*Evidence, error) {
    evidenceBytes, err := ctx.GetStub().GetState(id)
    if err != nil {
        return nil, fmt.Errorf("failed to read evidence: %v", err)
    }
    var evidence Evidence
    json.Unmarshal(evidenceBytes, &evidence)
    return &evidence, nil
}

func main() {
    chaincode, err := contractapi.NewChaincode(&ForensicChaincode{})
    if err != nil {
        fmt.Printf("Error creating chaincode: %s", err.Error())
        return
    }
    if err := chaincode.Start(); err != nil {
        fmt.Printf("Error starting chaincode: %s", err.Error())
    }
}
