#!/bin/bash 

echo "Run self-enryption - decryption"
go run main.go -mode "decryption" \
                    -chunk_dir "./data/test2/encrypted_chunks_2" \
                    -decry_data_dir "./data/test2/decrypted_data_2" \
                    -data_name_after_decryption "DecryptedData" \
                    -data_ext "pdf" \
                    -keys_dir "./data/test2/keys_2" \
                    -ID_dir "./data/test2/MSP_2" \
                    -ID_name "cert" \
                    -sig_dir "./data/test2/MSP_2" \
                    -sig_name "signature"
