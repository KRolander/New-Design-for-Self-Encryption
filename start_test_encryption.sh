#!/bin/bash 

echo "Run self-enryption - encryption"
go run main.go -mode "encryption" \
                -data_dir "./data" \
                -data_name "SelfEncryptingData" \
                -data_ext "pdf" \
                -num_chunks 4 \
                -chunk_ext "txt" \
                -encry_data_dir "./data/test2/encrypted_chunks_2" \
                -keys_dir "./data/test2/keys_2" \
                -refs_dir  "./data/test2/references_2" \
                -keys_ext "txt" \
                -ID_dir "./data/test2/MSP/signcerts" \
                -ID_name "cert" \
                -privKey_dir "./data/test2/MSP/keystore" \
                -privKey_name "sk" \
                -cmd_write true