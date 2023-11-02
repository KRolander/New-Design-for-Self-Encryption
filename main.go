//  Copyright (c) 2022 TU Delft - IRIS project. All rights reserved.
// Author: Roland Kromes - R.G.Kromes@tudelft.nl

package main

import (
	"github.com/KRolander/New-Design-for-Self-Encryption/tools"
	// "bytes"
	// "crypto/aes"
	// "crypto/cipher"
	// "encoding/hex"
	// "crypto/sha256"
	// "errors"
	"flag"
	"fmt"
)

var (
	initialVector = "1234567890123456"
)

type ErrorOptions struct {
	Option []string
}

func main() {
	fmt.Println("**** In Self-Encryption ****")

	mode := flag.String("mode", "", "specify the mode: encryption or decryption")

	inputDirectoryDataToEncrypt := flag.String("data_dir", "", "In encryption mode: specify the Input directory of data: (e.g., ./data)")

	nameOfDataToEncrypt := flag.String("data_name", "", "In encryption mode: specify the Name of the file to encrypt")

	dataExtetnion := flag.String("data_ext", "", "In both mode: specify the data extetntion, same for the data to encrypt and the decrypted data")

	numbertOfChunks := flag.Int("num_chunks", 0, "In encryption mode: specify the number of chunks, should be at least 3")

	extentionOfChunks := flag.String("chunk_ext", "", "In encryption mode: specify the encrypted chunks extetntion")

	outputDirectoryEncryption := flag.String("encry_data_dir", "", "In encryption mode: specify the output directory of data")

	directoryKeys := flag.String("keys_dir", "", "In both mode: specify the directory of the keys generated for the encryption")

	extentionOfKeys := flag.String("keys_ext", "", "In encryption mode: specify the desired extention of the keys generated for the encryption")

	outputDirectoryRefs := flag.String("refs_dir", "", "In encryption mode: specify the directory of the generated references (hashes of the encrypted data) for the encryption")

	directoryOfIdentitiy := flag.String("ID_dir", "", "In both mode: specify the directory of the Identity (ID) read/write -> encryption/decryption")

	nameOfIdentity := flag.String("ID_name", "", "In both mode: specify the name of the Identity (ID) -> it is a .pem file")

	inputDirectoryOfPrivateKey := flag.String("privKey_dir", "", "In encryption mode: specify the direction of the private key")

	nameOfPrivateKey := flag.String("privKey_name", "", "In encryption mode: specify the name of the private key")

	produceWriteValues := flag.Bool("cmd_write", false, "In encryption mode: specify if the results should be written to the directories or not (true/false)")

	outputDirectoryDecryption := flag.String("decry_data_dir", "", "In decryption mode: specify the output directory of the decrypted data")

	nameOfDataAfterDecrytpion := flag.String("data_name_after_decryption", "", "In decryption mode: specify the desired Name of the file after decryption")

	directorySignature := flag.String("sig_dir", "", "In decryption mode: the directory of the signature")

	nameOfSignature := flag.String("sig_name", "", "In decryption mode: specify the desired Name of the signature file (its extention is .txt by default)")

	chunksDirectory := flag.String("chunk_dir", "", "In decryption mode: specify the directory of the encrypted chunks")
	flag.Parse()

	// fmt.Println("mode : ", *mode)
	// fmt.Println("data_dir : ", *inputDirectoryDataToEncrypt)
	// fmt.Println("data_name : ", *nameOfDataToEncrypt)
	// fmt.Println("data_ext : ", *dataExtetnion)
	// fmt.Println("num_chunks : ", *numbertOfChunks)
	// fmt.Println("chunk_ext : ", *extentionOfChunks)
	// fmt.Println("encry_data_dir : ", *outputDirectoryEncryption)
	// fmt.Println("keys_dir : ", *directoryKeys)
	// fmt.Println("key_ext : ", *extentionOfKeys)
	// fmt.Println("refs_dir : ", *outputDirectoryRefs)
	// fmt.Println("ID_dir :", *directoryOfIdentitiy)
	// fmt.Println("ID_name : ", *nameOfIdentity)
	// fmt.Println("PrivKey_dir : ", *inputDirectoryOfPrivateKey)
	// fmt.Println("PrivKey_name :", *nameOfPrivateKey)
	// fmt.Println("cmd_write :", *produceWriteValues)

	var options ErrorOptions

	if *mode == "" {
		options.Option = append(options.Option, "-mode")
	}

	if *mode != "" {
		if *mode == "encryption" {

			if *inputDirectoryDataToEncrypt == "" {
				options.Option = append(options.Option, "-data_dir")
			}

			if *nameOfDataToEncrypt == "" {
				options.Option = append(options.Option, "-data_name")
			}

			if *dataExtetnion == "" {
				options.Option = append(options.Option, "-data_ext")
			}

			if *numbertOfChunks < 3 {
				options.Option = append(options.Option, "-num_chunks")
			}

			if *extentionOfChunks == "" {
				options.Option = append(options.Option, "-chunk_ext")
			}

			if *outputDirectoryEncryption == "" {
				options.Option = append(options.Option, "-encry_data_dir")
			}

			if *directoryKeys == "" {
				options.Option = append(options.Option, "-keys_dir")
			}

			if *outputDirectoryRefs == "" {
				options.Option = append(options.Option, "-refs_dir")
			}

			if *extentionOfKeys == "" {
				options.Option = append(options.Option, "-keys_ext")
			}

			if *directoryOfIdentitiy == "" {
				options.Option = append(options.Option, "-ID_dir")
			}

			if *nameOfIdentity == "" {
				options.Option = append(options.Option, "-ID_name")
			}

			if *inputDirectoryOfPrivateKey == "" {
				options.Option = append(options.Option, "-privKey_dir")
			}

			if *nameOfPrivateKey == "" {
				options.Option = append(options.Option, "-privKey_name")
			}

			if *produceWriteValues == false {
				options.Option = append(options.Option, "-cmd_write")
			}

			if options.Option != nil {
				fmt.Println("Incorrect input parameters at : ")
				fmt.Printf("---------------------------------------------------\n")

				for _, param := range options.Option {
					fmt.Println(param)
				}
				fmt.Println("Please refer to -h or --help option to get more information how to use the program")

			} else {
				tools.SelfEncryptData(*inputDirectoryDataToEncrypt, *nameOfDataToEncrypt, *dataExtetnion, *numbertOfChunks,
					*extentionOfChunks, *outputDirectoryEncryption, *directoryKeys, *extentionOfKeys, *outputDirectoryRefs, *directoryOfIdentitiy, *nameOfIdentity, *inputDirectoryOfPrivateKey, *nameOfPrivateKey, *produceWriteValues)

				// tools.SelfEncryptData("./data", "SelfEncryptingData", "pdf", 4, "txt", "./data/test2/encrypted_chunks_2", "./data/test2/keys_2", "txt", "./data/test2/references_2", "./data/test2/MSP/signcerts", "cert", "./data/test2/MSP/keystore", "sk", true)
			}

		} else if *mode == "decryption" {

			if *chunksDirectory == "" {
				options.Option = append(options.Option, "-chunk_dir")
			}

			if *outputDirectoryDecryption == "" {
				options.Option = append(options.Option, "-decry_data_dir")
			}

			if *nameOfDataAfterDecrytpion == "" {
				options.Option = append(options.Option, "-data_name_after_decryption")
			}

			if *dataExtetnion == "" {
				options.Option = append(options.Option, "-data_ext")
			}

			if *directoryKeys == "" {
				options.Option = append(options.Option, "-keys_dir")
			}

			if *directoryOfIdentitiy == "" {
				options.Option = append(options.Option, "-ID_dir")
			}

			if *nameOfIdentity == "" {
				options.Option = append(options.Option, "-ID_name")
			}

			if *directorySignature == "" {
				options.Option = append(options.Option, "-sig_dir")
			}

			if *nameOfSignature == "" {
				options.Option = append(options.Option, "-sig_name")
			}

			if options.Option != nil {
				fmt.Println("Incorrect input parameters at : ")
				fmt.Printf("---------------------------------------------------\n")

				for _, param := range options.Option {
					fmt.Println(param)
				}
				fmt.Println("Please refer to -h or --help option to get more information how to use the program")

			} else {

				// tools.SelfDecryptData("./data/test2/encrypted_chunks_2", "DecryptedData", "pdf", "./data/test2/decrypted_data_2", "./data/test2/keys_2", "./data/test2/MSP_2", "cert", "./data/test2/MSP_2", "signature")
				tools.SelfDecryptData(*chunksDirectory, *nameOfDataAfterDecrytpion, *dataExtetnion, *outputDirectoryDecryption, *directoryKeys, *directoryOfIdentitiy, *nameOfIdentity, *directorySignature, *nameOfSignature)

			}
		} else {

		}

	} else {
		fmt.Println("Incorrect input parameters at : ")
		for _, param := range options.Option {
			fmt.Println(param)
		}
		fmt.Println("Please refer to -h or --help option to get more information how to use the program")

	}

	// if (options.Option != nil){
	// 	fmt.Println("Incorrect input parameters at : ")
	// 	for _, param := range options.Option {
	// 		fmt.Println(param)
	// 	}
	// 	fmt.Println("Please refer to -h or --help option to get more information how to use the program")

	// }else{
	// 	if (*mode == "encryption") {
	// 		tools.SelfEncryptData("./data", "SelfEncryptingData", "pdf", 4, "txt", "./data/test2/encrypted_chunks_2", "./data/test2/keys_2", "txt", "./data/test2/references_2", "./data/test2/MSP/signcerts", "cert", "./data/test2/MSP/keystore", "sk", true)
	// 	}else{
	// 		tools.SelfDecryptData("./data/test2/encrypted_chunks_2", "DecryptedData", "pdf", "./data/test2/decrypted_data_2", "./data/test2/keys_2", "./data/test2/MSP_2", "cert", "./data/test2/MSP_2", "signature")
	// 	}
	// }

	// h:= sha256.New()

	// h.Write([]byte("Hello World"))

	// hash_digest := h.Sum(nil) // return []byte
	// fmt.Printf("%x\n", hash_digest)

	// hash_1_str := "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
	// hash_1, err := hex.DecodeString(hash_1_str)
	// if err != nil {
	// 	panic(err)
	// }

	// hash_2_str := "24ca024108df228d0ef370cb7d45c86d78deda29ff3e735646059c6c3ff0130a"
	// hash_2, err := hex.DecodeString(hash_2_str)
	// if err != nil {
	// 	panic(err)
	// }

	// hash_Obj := Hash(hash_1)
	// fmt.Printf("%x\n", hash_Obj)

	// hash_Obj_2 := Hash(hash_2)
	// fmt.Printf("%x\n", hash_Obj_2)

	// data, lengthOfData := tools.ReadData("./data", "small", "png")

	// tabOfChunks :=  tools.CreateDataChunksChunkType(data,lengthOfData, 4)

	// tools.SelfEncryptData("./data", "small", "png", 4, "txt", "./data/test2/encrypted_chunks", "./data/test2/keys", "txt", "./data/test2/references", true)

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// tools.SelfEncryptData("./data", "SelfEncryptingData", "pdf", 4, "txt", "./data/test2/encrypted_chunks_2", "./data/test2/keys_2", "txt", "./data/test2/references_2", true)

	// _, _, res_EncrTabHash := tools.SelfEncryptData("./data", "SelfEncryptingData", "pdf", 4, "txt", "./data/test2/encrypted_chunks_2", "./data/test2/keys_2", "txt", "./data/test2/references_2", true)

	// fmt.Println("The first hash is : ", hex.EncodeToString(res_EncrTabHash.Hash_Tab_Elements[0]))

	// dataTab := tools.CreateDataChunksChunkType(data,lengthOfData, 4)

	// fmt.Println("/////////////////////////////////////////////////")
	// fmt.Printf("dataTab[0]:%s\n", string(dataTab[0]))
	// fmt.Printf("dataTab[1]:%s\n", string(dataTab[1]))
	// fmt.Printf("dataTab[2]:%s\n", string(dataTab[2]))
	// fmt.Printf("dataTab[3]:%s\n", string(dataTab[3]))
	// fmt.Println("/////////////////////////////////////////////////")

	// s0 := string(dataTab[0])
	// s1 := string(dataTab[1])
	// s2 := string(dataTab[2])
	// s3 := string(dataTab[3])

	// tabOfChunks := tools.Chunk_Tab{Chunk_Tab_Elements:dataTab, Num_Chunk_Tab_Elements:4}

	fmt.Printf("---------------------------------------------------\n")
	// fmt.Printf(" Lenght of string %x lenght of byte %x\n", len(s0), len(dataTab[0]))

	// chunk1 := tools.Chunk(s0)
	// chunk2 := tools.Chunk(s1)
	// chunk3 := tools.Chunk(s2)
	// chunk4 := tools.Chunk(s3)

	// chunk1 := tools.Chunk(dataTab[0])
	// chunk2 := tools.Chunk(dataTab[1])
	// chunk3 := tools.Chunk(dataTab[2])
	// chunk4 := tools.Chunk(dataTab[3])

	// chunk1 := tools.Chunk("Hello World\n")
	// chunk2 := tools.Chunk("Goodbye Worl")
	// chunk3 := tools.Chunk("Hy World")
	// chunk4 := tools.Chunk("Hi World")

	// chunk1 := tools.Chunk("Hello World")
	// chunk2 := tools.Chunk("\nGoodbye Wo")
	// chunk3 := tools.Chunk("rld\nHy Worl")
	// chunk4 := tools.Chunk("d\nHi World\n")

	// var tabOfChunks tools.Chunk_Tab;

	// tabOfChunks := tools.Chunk_Tab{
	// 	Chunk_Tab_Elements:	make([]tools.Chunk, 4),
	// 	Num_Chunk_Tab_Elements: 4,
	// }

	// for i:=0; i<4; i++{
	// 	tabOfChunks.Chunk_Tab_Elements[i] =  tools.Chunk(string(dataTab[i]))

	// }

	// tabOfChunks := tools.Chunk_Tab{
	// 	Chunk_Tab_Elements:	make([]tools.Chunk, 4),
	// 	Num_Chunk_Tab_Elements: 4,
	// }

	// copy(tabOfChunks.Chunk_Tab_Elements, dataTab)

	// tabOfChunks.Chunk_Tab_Elements = make([]tools.Chunk, 0)

	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, dataTab[0])
	// tabOfChunks.IncrNumElements()

	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, dataTab[1])
	// tabOfChunks.IncrNumElements()

	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, dataTab[2])
	// tabOfChunks.IncrNumElements()

	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, dataTab[3])
	// tabOfChunks.IncrNumElements()

	// var tabOfChunks tools.Chunk_Tab;
	// tabOfChunks.Chunk_Tab_Elements = make([]tools.Chunk, 0)

	////////////////////////////////////////////////////////////////////////////////////////////////////////
	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, tools.Chunk(string(dataTab[0])))
	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, tools.Chunk(string(dataTab[1])))
	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, tools.Chunk(string(dataTab[2])))
	// tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, tools.Chunk(string(dataTab[3])))
	////////////////////////////////////////////////////////////////////////////////////////////////////////

	// tabOfChunks := tools.Chunk_Tab{Chunk_Tab_Elements : []tools.Chunk{dataTab[0],dataTab[1], dataTab[2], dataTab[3]}, Num_Chunk_Tab_Elements : 4}

	// fmt.Println("/////////////////////////////////////////////////")
	// fmt.Printf("A chunk %s\n", tabOfChunks.Chunk_Tab_Elements[0])
	// fmt.Printf("A chunk %s\n", tabOfChunks.Chunk_Tab_Elements[1])
	// fmt.Printf("A chunk %s\n", tabOfChunks.Chunk_Tab_Elements[2])
	// fmt.Printf("A chunk %s\n", tabOfChunks.Chunk_Tab_Elements[3])
	// fmt.Println("/////////////////////////////////////////////////")

	// var tabOfHash Hash_Tab;

	// tabOfHash.CreateHahsTab()
	// fmt.Printf("A Hash %x\n", tabOfHash.Hash_Tab_Elements[0])

	// tabOfHash.CreateHahsTab()
	// fmt.Printf("A Hash second %x\n", tabOfHash.Hash_Tab_Elements[1])

	// Create a Hash Table with filled out with the hash values of
	// all of the chunks
	// var tabOfHash tools.Hash_Tab;
	// tabOfHash.CreateHahsTab(tabOfChunks)

	// fmt.Printf("Hash of chunk %x numbert of elements : %d \n", tabOfHash.Hash_Tab_Elements[0], tabOfHash.Num_Hash_Tab_Elements)
	// fmt.Printf("Hash of chunk %x numbert of elements : %d \n", tabOfHash.Hash_Tab_Elements[1], tabOfHash.Num_Hash_Tab_Elements)
	// fmt.Printf("Hash of chunk %x numbert of elements : %d \n", tabOfHash.Hash_Tab_Elements[2], tabOfHash.Num_Hash_Tab_Elements)
	// fmt.Printf("Hash of chunk %x numbert of elements : %d \n", tabOfHash.Hash_Tab_Elements[3], tabOfHash.Num_Hash_Tab_Elements)

	/////////////////////// Test on encryption-decryption ///////////////////////
	// fmt.Printf("Clear text : %x\n",tabOfChunks.Chunk_Tab_Elements[0])

	// key := Key("1234567890123456")
	// iv := IV("1234567890123456")
	// encodedChunk := encodeChunk(tabOfChunks.Chunk_Tab_Elements[0], key, iv)

	// fmt.Printf("Result: Encrypted chunk : %x\n",encodedChunk)

	// decryptChunk(encodedChunk, key, iv)
	///////////////////////////////////////////////////////////////////////////

	// key, iv := createKeyandIV(tabOfHash.Hash_Tab_Elements[0])
	// var key_iv_tab tools.Key_IV_Tab;
	// key_iv_tab.CreateKeyandIV_Tab(tabOfHash)

	// fmt.Printf("Key : %x   IV : %x \n", key_iv_tab.Key_Elements[0], key_iv_tab.IV_Elements[0])
	// fmt.Printf("Key : %x   IV : %x \n", key_iv_tab.Key_Elements[1], key_iv_tab.IV_Elements[1])
	// fmt.Printf("Key : %x   IV : %x \n", key_iv_tab.Key_Elements[2], key_iv_tab.IV_Elements[2])
	// fmt.Printf("Key : %x   IV : %x \n", key_iv_tab.Key_Elements[3], key_iv_tab.IV_Elements[3])

	// var enc_tab tools.EncryptedChunk_Tab;
	// enc_tab.CreateEncryptedChunkTab(tabOfChunks,tabOfHash)

	// fmt.Printf("Encrypted Cunk %x \n", enc_tab.EncryptedChunk_Tab_Elements[0])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab.EncryptedChunk_Tab_Elements[1])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab.EncryptedChunk_Tab_Elements[2])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab.EncryptedChunk_Tab_Elements[3])

	// decryptChunk(enc_tab.EncryptedChunk_Tab_Elements[0], key_iv_tab.Key_Elements[0], key_iv_tab.IV_Elements[0])

	// p0 := [][]byte(enc_tab.EncryptedChunk_Tab_Elements)

	// toEncrypt := [][]byte{[]byte{enc_tab.EncryptedChunk_Tab_Elements}}

	// p1 := enc_tab.EncryptedChunk_Tab_Elements[0]
	// p2 := enc_tab.EncryptedChunk_Tab_Elements[1]
	// p3 := enc_tab.EncryptedChunk_Tab_Elements[2]
	// p4 := enc_tab.EncryptedChunk_Tab_Elements[3]

	// toEncrypt := [][]byte{p1,p2,p3,p4}

	// tools.WriteChunksTypeEncryptedChunk(enc_tab.EncryptedChunk_Tab_Elements, 4, "./data/dataChunks", "dataTestChunk", "txt")

	////////////////////////////////////////////// XoR TAB ////////////////////////////////////////
	// var x_tab tools.Xelement_Tab;
	// x_tab.CreateXelement_Tab(tabOfHash)
	/////////////////////////////////////////////////////////////////////////////////////////////

	// fmt.Printf("Xelement %x \n", len(x_tab.Xelement_Tab_Elements[0]))
	// fmt.Printf("Xelement %x \n", len(x_tab.Xelement_Tab_Elements[1]))
	// fmt.Printf("Xelement %x \n", len(x_tab.Xelement_Tab_Elements[2]))
	// fmt.Printf("Xelement %x \n", len(x_tab.Xelement_Tab_Elements[3]))

	// fmt.Printf("Xelement %x \ncreateKeyandIV_Tab", x_tab.Xelement_Tab_Elements[0])
	// fmt.Printf("Xelement %x \n", x_tab.Xelement_Tab_Elements[1])
	// fmt.Printf("Xelement %x \n", x_tab.Xelement_Tab_Elements[2])
	// fmt.Printf("Xelement %x \n", x_tab.Xelement_Tab_Elements[3])

	// Test of First Level decryption
	// encodedChunksToRead := tools.ReadDataChunks("./data/dataChunks")
	// var enc_tab_v2 tools.EncryptedChunk_Tab;

	// enc_tab_v2.EncryptedChunk_Tab_Elements = append(enc_tab_v2.EncryptedChunk_Tab_Elements, encodedChunksToRead[0])
	// enc_tab_v2.EncryptedChunk_Tab_Elements = append(enc_tab_v2.EncryptedChunk_Tab_Elements, encodedChunksToRead[1])
	// enc_tab_v2.EncryptedChunk_Tab_Elements = append(enc_tab_v2.EncryptedChunk_Tab_Elements, encodedChunksToRead[2])
	// enc_tab_v2.EncryptedChunk_Tab_Elements = append(enc_tab_v2.EncryptedChunk_Tab_Elements, encodedChunksToRead[3])

	// fmt.Println("///////////////////////////////////////////////////////////////////////")
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab_v2.EncryptedChunk_Tab_Elements[0])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab_v2.EncryptedChunk_Tab_Elements[1])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab_v2.EncryptedChunk_Tab_Elements[2])
	// fmt.Printf("Encrypted Cunk %x \n", enc_tab_v2.EncryptedChunk_Tab_Elements[3])
	// fmt.Println("///////////////////////////////////////////////////////////////////////")

	// var dec_tab tools.DecryptedChunk_Tab;
	// dec_tab.CreateDecryptedChunkTab(enc_tab, tabOfHash)

	// fmt.Printf("Decrypted Chunk %s \n", string(dec_tab.DecryptedChunk_Tab_Elements[0]))
	// fmt.Printf("Decrypted Chunk %s \n", string(dec_tab.DecryptedChunk_Tab_Elements[1]))
	// fmt.Printf("Decrypted Chunk %s \n", string(dec_tab.DecryptedChunk_Tab_Elements[2]))
	// fmt.Printf("Decrypted Chunk %s \n", string(dec_tab.DecryptedChunk_Tab_Elements[3]))

	// var dec_tab_v2 tools.DecryptedChunk_Tab;

	// dec_tab_v2.CreateDecryptedChunkTab(enc_tab_v2, tabOfHash)

	// fmt.Println("///////////////////////////////////////////////////////////////////////")
	// fmt.Printf("Decrypted Chunk %x \n", dec_tab_v2.DecryptedChunk_Tab_Elements[0])
	// fmt.Printf("Decrypted Chunk %x \n", dec_tab_v2.DecryptedChunk_Tab_Elements[1])
	// fmt.Printf("Decrypted Chunk %x \n", dec_tab_v2.DecryptedChunk_Tab_Elements[2])
	// fmt.Printf("Decrypted Chunk %x \n", dec_tab_v2.DecryptedChunk_Tab_Elements[3])
	// fmt.Println("///////////////////////////////////////////////////////////////////////")

	// finalDataToDecrypt := [][]byte{dec_tab_v2.DecryptedChunk_Tab_Elements[0], dec_tab_v2.DecryptedChunk_Tab_Elements[1], dec_tab_v2.DecryptedChunk_Tab_Elements[2], dec_tab_v2.DecryptedChunk_Tab_Elements[3]}
	// finalDecryptedData := tools.CreateFinalFile(finalDataToDecrypt)

	// tools.WriteData(finalDecryptedData, "./data/test", "CombinedDataNew.png")

	////////////////////////////////////////////// XoR 2nd Levle Encryption ////////////////////////////////////////
	// enc_tab.CreateSecondLevel_EncryptedChunkTab(x_tab)
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// tools.MyCompare(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1], res_tmp)

	// tools.MyCompare(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1], res_tmp_2)

	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", len(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[0]))
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", len(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1]))
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", len(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[2]))
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", len(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[3]))

	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[0])
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1])
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[2])
	// fmt.Printf("SecondLevel_EncryptedChunk %x \n", enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[3])

	//  enc_tab.EncryptedChunk_SecondLevel_Tab_Elements

	// EXres := XoR(x_tab.Xelement_Tab_Elements[0], enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[0])
	// fmt.Printf("createSecondLevel_EncryptedChunkTab back %x \n", EXres)
	// EXres = XoR(x_tab.Xelement_Tab_Elements[1], enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1])
	// fmt.Printf("createSecondLevel_EncryptedChunkTab back %x \n", EXres)
	// EXres = XoR(x_tab.Xelement_Tab_Elements[2], enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[2])
	// fmt.Printf("createSecondLevel_EncryptedChunkTab back %x \n", EXres)
	// EXres = XoR(x_tab.Xelement_Tab_Elements[3], enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[3])
	// fmt.Printf("createSecondLevel_EncryptedChunkTab back %x \n", EXres)

	////////////////////////////////////////////// XoR 2nd Levle Encryption ////////////////////////////////////////
	// dec_tab.CreateSecondLevel_DecryptedChunkTab(enc_tab, x_tab)
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// var dec_2n_tab tools.DecryptedChunk_Tab;

	// dec_2n_tab.CreateSecondLevel_DecryptedChunkTab(enc_tab, x_tab)

	// final2ndLevelDataToDecrypt := [][]byte{dec_2n_tab.DecryptedChunk_SecondLevel_Tab_Elements[0], dec_2n_tab.DecryptedChunk_SecondLevel_Tab_Elements[1], dec_2n_tab.DecryptedChunk_SecondLevel_Tab_Elements[2], dec_2n_tab.DecryptedChunk_SecondLevel_Tab_Elements[3]}

	// var dec_tab_v3 tools.DecryptedChunk_Tab;

	// var enc_tab_v3 tools.EncryptedChunk_Tab;

	// enc_tab_v3.EncryptedChunk_Tab_Elements = append(enc_tab_v3.EncryptedChunk_Tab_Elements, final2ndLevelDataToDecrypt[0])
	// enc_tab_v3.EncryptedChunk_Tab_Elements = append(enc_tab_v3.EncryptedChunk_Tab_Elements, final2ndLevelDataToDecrypt[1])
	// enc_tab_v3.EncryptedChunk_Tab_Elements = append(enc_tab_v3.EncryptedChunk_Tab_Elements, final2ndLevelDataToDecrypt[2])
	// enc_tab_v3.EncryptedChunk_Tab_Elements = append(enc_tab_v3.EncryptedChunk_Tab_Elements, final2ndLevelDataToDecrypt[3])

	// dec_tab_v3.CreateDecryptedChunkTab(enc_tab_v3, tabOfHash)

	// finalDataToDecrypt_v2 := [][]byte{dec_tab_v3.DecryptedChunk_Tab_Elements[0], dec_tab_v3.DecryptedChunk_Tab_Elements[1], dec_tab_v3.DecryptedChunk_Tab_Elements[2], dec_tab_v3.DecryptedChunk_Tab_Elements[3]}

	// final2ndLevelDecryptedData := tools.CreateFinalFile(finalDataToDecrypt_v2)
	// tools.WriteData(final2ndLevelDecryptedData, "./data/test", "CombinedDataNew2ndLevel.png")

	// res_tmp_2 := tools.SelfDecryptData("./data/test2/encrypted_chunks", "DecryptedData", "png", "./data/test2/decrypted_data", "./data/test2/keys")

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// tools.SelfDecryptData("./data/test2/encrypted_chunks_2", "DecryptedData", "pdf", "./data/test2/decrypted_data_2", "./data/test2/keys_2")

	// tools.MyCompare(dec_2n_tab.DecryptedChunk_SecondLevel_Tab_Elements[1], res_tmp_2)

	// fmt.Printf("Second Level decrypted_chunk : %x \n",dec_tab.DecryptedChunk_SecondLevel_Tab_Elements[0])
	// fmt.Printf("Second Level decrypted_chunk : %x \n",dec_tab.DecryptedChunk_SecondLevel_Tab_Elements[1])
	// fmt.Printf("Second Level decrypted_chunk : %x \n",dec_tab.DecryptedChunk_SecondLevel_Tab_Elements[2])
	// fmt.Printf("Second Level decrypted_chunk : %x \n",dec_tab.DecryptedChunk_SecondLevel_Tab_Elements[3])

	////////////////////////////////////////////// XoR 2nd Levle Encryption ////////////////////////////////////////
	// var h_enc tools.Hash_Encrypted_Tab;
	// h_enc.CreateHash_Encrypted_Tab(enc_tab)
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// x1 := EncryptedChunk{0x96, 0x89, 0x3, 0x77}
	// x2 := Xelement{0x23, 0x7}
	// res := XoR(x2, x1)
	// fmt.Printf("XoR : %x\n", res)

	// res1 := XoR(x2, res)
	// fmt.Printf("XoR back : %x\n", res1)

	// tools.Hello()
	// data, lengthOfData := tools.ReadData("./data", "test", "txt")

	// fmt.Printf("Data: %s\n", data)
	// fmt.Printf("Length: %d\n", lengthOfData)

	// RW := RW_tool.New()

	// TabDataChunk := tools.New()
	// TabDataChunk := tools.DataChunks{}
	// var val int
	// val = 8
	// TabDataChunk.LetChunkedData(val)

	// // TabDataChunk.createDataChunks(9)
	// fmt.Printf("Data: %x\n", TabDataChunk.NumOfChunks)
	// dataTab := tools.CreateDataChunks(data,lengthOfData, 4)

	// tools.WriteChunks(dataTab, 4, "./data/dataChunks", "dataTestChunk", "o")

	// // data1, _ := tools.ReadData("./data/dataChunks", "dataTestChunk_0", "o")
	// // data2, _ := tools.ReadData("./data/dataChunks", "dataTestChunk_1", "o")
	// // data3, _ := tools.ReadData("./data/dataChunks", "dataTestChunk_2", "o")

	// // combinedData := tools.CreateFinalFile(data1,data2,data3)

	// // fmt.Println("Combined Data : ", combinedData)
	// // tools.WriteData(combinedData, "./data", "CombinedData.txt")
	// // tools.WriteData("./data", "dataTestwrite.tex")

	// bigData := tools.ReadDataChunks("./data/dataChunks")
	// combinedBigData := tools.CreateFinalFile(bigData)

	// tools.WriteData(combinedBigData, "./data/test", "CombinedData.txt")

	////////////////////////////// Working RW tools //////////////////////////////
	// data, lengthOfData := tools.ReadData("./data", "test", "txt")
	// dataTab := tools.CreateDataChunks(data,lengthOfData, 4)
	// tools.WriteChunks(dataTab, 4, "./data/dataChunks", "dataTestChunk", "o")

	// bigData := tools.ReadDataChunks("./data/dataChunks")
	// combinedBigData := tools.CreateFinalFile(bigData)

	// tools.WriteData(combinedBigData, "./data/test", "CombinedData.txt")
	/////////////////////////////////////////////////////////////////////////////

}

////////////////////////////////////// Annexes //////////////////////////////////////

//////////////////// Initialize the Hash_Tab method 1 /////////////////
// tabOfHash := Hash_Tab{
// 	Hash_Tab_Elements: []Hash{hash_Obj, hash_Obj_2},
// 	Num_Hash_Tab_Elements: 2,
// }

// fmt.Printf("%x\n", tabOfHash.Hash_Tab_Elements[0])

//////////////////// Initialize the Hash_Tab method 2 /////////////////
// var tabOfHash Hash_Tab;

// tabOfHash.Hash_Tab_Elements = make([]Hash, 0)

// tabOfHash.Hash_Tab_Elements = append(tabOfHash.Hash_Tab_Elements, hash_Obj)
// tabOfHash.Hash_Tab_Elements = append(tabOfHash.Hash_Tab_Elements, hash_Obj_2)

// fmt.Printf("%x\n", tabOfHash.Hash_Tab_Elements[0])

//////////////////////////////////////////////////////////////////////////////////////

// Key : a591a6d40bf420404a011733cfb7b190   IV : d62c65bf0bcda32b57b277d9ad9f146e
// Key : c96724127af2d6f56bbc3898632b1011   IV : 67242f02519a99e5ab3f1cab9ff995e7
// Key : e7f4e10777f8b7af0c0afbc3b219267b   IV : ea38dc863271893ddea0decb620302d0

// Hello World
// encrypted_chunk : 6100fd12308663e1e8a2c1ffe988cf47
// Goodbye World
// encrypted_chunk : 751765d06cba62bc85f466efd74fe228
// Hy World
// encrypted_chunk : 1d9a5ed01c39597ce7cb6b7c28f03d21
// Hi World
