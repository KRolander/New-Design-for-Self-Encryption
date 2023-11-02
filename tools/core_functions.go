//  Copyright (c) 2022 TU Delft - IRIS project. All rights reserved.
// Author: Roland Kromes - R.G.Kromes@tudelft.nl

package tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	// "encoding/asn1"
	"crypto/x509"
	// "crypto/x509/pkix"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
)

type Hash []byte

type Hash_Tab struct {
	Hash_Tab_Elements     []Hash
	Num_Hash_Tab_Elements int
}

type Hash_Encrypted_Tab struct {
	Hash_Encrypted_Tab_Elements     []Hash
	Num_Hash_Encrypted_Tab_Elements int
}

type Chunk []byte
type EncryptedChunk []byte
type DecryptedChunk []byte

type EncryptedChunk_Tab struct {
	EncryptedChunk_Tab_Elements     []EncryptedChunk
	Num_EncryptedChunk_Tab_Elements int

	EncryptedChunk_SecondLevel_Tab_Elements []EncryptedChunk
	Num_EncryptedChunk_SecondLevel_Elements int
}

type DecryptedChunk_Tab struct {
	DecryptedChunk_Tab_Elements     []DecryptedChunk
	Num_DecryptedChunk_Tab_Elements int
	totalSize                       int

	DecryptedChunk_SecondLevel_Tab_Elements     []DecryptedChunk
	Num_DecryptedChunk_SecondLevel_Tab_Elements int
}

type Key []byte
type IV []byte
type Xelement []byte

type Xelement_Tab struct {
	Xelement_Tab_Elements     []Xelement
	Num_Xelement_Tab_Elements int
}

type Key_IV_Tab struct {
	Key_Elements     []Key
	Num_Key_Elements int

	IV_Elements     []IV
	Num_IV_Elements int
}

type Chunk_Tab struct {
	Chunk_Tab_Elements     []Chunk
	Num_Chunk_Tab_Elements int
}

// Increments the number of emelements of the Xelement Tab
func (x_tab *Xelement_Tab) IncrNumElements() {
	x_tab.Num_Xelement_Tab_Elements++
}

// Increments the number of emelements of the Encrypted Chunk Tab
func (enc_tab *EncryptedChunk_Tab) IncrNumElements() {
	enc_tab.Num_EncryptedChunk_Tab_Elements++
}

// Increments the number of second level encrypted emelements of the Encrypted Chunk Tab
func (enc_tab *EncryptedChunk_Tab) IncrNumElementsSecondLevel() {
	enc_tab.Num_EncryptedChunk_SecondLevel_Elements++
}

func (dec_tab *DecryptedChunk_Tab) IncrNumElements() {
	dec_tab.Num_DecryptedChunk_Tab_Elements++
}

func (dec_tab *DecryptedChunk_Tab) IncTotalSize(sizeOfChunk int) {
	dec_tab.totalSize = dec_tab.totalSize + sizeOfChunk
}

func (dec_tab *DecryptedChunk_Tab) IncrNumElementsSecondLevel() {
	dec_tab.Num_DecryptedChunk_SecondLevel_Tab_Elements++
}

// Increments the number of emelements of the Key IV Tab
func (key_iv_tab *Key_IV_Tab) IncrNumElements() {
	key_iv_tab.Num_Key_Elements++
	key_iv_tab.Num_IV_Elements++
}

// Increments the number of emelements of the Chunk Tab
func (c_tab *Chunk_Tab) IncrNumElements() {
	c_tab.Num_Chunk_Tab_Elements++
}

// Compute the SHA-256 hash function
func computeHash(c Chunk) Hash {
	h := sha256.New()
	h.Write(c)

	hash_digest := h.Sum(nil) // return []byte

	return Hash(hash_digest)
}

// Compute the SHA-512 hash function
func computeHashSHA_512(c Chunk) Hash {
	h := sha512.New()
	h.Write(c)

	hash_digest := h.Sum(nil) // return []byte

	return Hash(hash_digest)
}

// Increments the number of emelements of the Hash Tab
func (h_tab *Hash_Tab) IncrNumElements() {
	h_tab.Num_Hash_Tab_Elements++
}

// Increments the number of emelements of the Hash Tab
// of second level encrypted chunks
func (h_tab *Hash_Encrypted_Tab) IncrNumElements() {
	h_tab.Num_Hash_Encrypted_Tab_Elements++
}

// Computes the hash of each of the chunks contained by the Chunk tab
// Append the hash values of the chunks to the Hash Tab
// First hash value corresponds to the first chunk, etc...
func (h_tab *Hash_Tab) CreateHahsTab(C_tab Chunk_Tab) {

	// fmt.Printf("In CreateHahsTab \n")

	for _, chunk := range C_tab.Chunk_Tab_Elements {
		// fmt.Printf("%x\n", chunk)
		hash_value := computeHash(chunk)
		h_tab.Hash_Tab_Elements = append(h_tab.Hash_Tab_Elements, hash_value)
		h_tab.IncrNumElements()
	}
}

// Can also considered as the Gen() key function used for typical ciphers
// Computes the hash of each of the chunks contained by the Chunk tab salted
// with 128 bit of randomness
// Append the hash values of the chunks to the Hash Tab
// First hash value corresponds to the first chunk + randomness, etc...
// Keys: H(chunk_1 || rand_1), ..., H(chunk_n || rand_n)
func (h_tab *Hash_Tab) CreateHahsTabWithRand(C_tab Chunk_Tab) {

	for _, chunk := range C_tab.Chunk_Tab_Elements {
		// fmt.Printf("%x\n", chunk)

		seed := make([]byte, 128) // 128 bit security parameter
		rand.Read(seed)

		chunkRand := chunk

		chunkRand = append(chunkRand, seed...)

		// hash_value := computeHash(chunkRand)
		hash_value := computeHashSHA_512(chunkRand)

		h_tab.Hash_Tab_Elements = append(h_tab.Hash_Tab_Elements, hash_value)
		h_tab.IncrNumElements()

	}

}

// Computes the hash of each of the encrypted chunks contained by the EncryptedChunk_Tab tab
// second level encrypted chunks
// Append the hash values of the chunks to the Hash Tab
// First hash value corresponds to the first chunk, etc...
func (h_tab *Hash_Tab) CreateHahsTabForEncryptedChunk(enc_tab EncryptedChunk_Tab) {

	// fmt.Printf("In CreateHahsTab \n")

	for _, chunk := range enc_tab.EncryptedChunk_SecondLevel_Tab_Elements {
		// fmt.Printf("%x\n", chunk)
		hash_value := computeHash(Chunk(chunk))
		h_tab.Hash_Tab_Elements = append(h_tab.Hash_Tab_Elements, hash_value)
		h_tab.IncrNumElements()
	}
}

var errPKCS7Padding = errors.New("pkcs7pad: bad padding")

// pkcs7strip remove pkcs7 padding
func pkcs7strip(buf []byte, blockSize int) ([]byte, error) {

	padLen := buf[len(buf)-1]
	toCheck := 255
	good := 1
	if toCheck > len(buf) {
		toCheck = len(buf)
	}
	for i := 0; i < toCheck; i++ {
		b := buf[len(buf)-1-i]

		outOfRange := subtle.ConstantTimeLessOrEq(int(padLen), i)
		equal := subtle.ConstantTimeByteEq(padLen, b)
		good &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	good &= subtle.ConstantTimeLessOrEq(1, int(padLen))
	good &= subtle.ConstantTimeLessOrEq(int(padLen), len(buf))

	if good != 1 {
		return nil, errPKCS7Padding
	}

	return buf[:len(buf)-int(padLen)], nil
}

// pkcs7pad add pkcs7 padding
func pkcs7pad(text []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 255 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		i := blockSize - (len(text) % blockSize)
		return append(text, bytes.Repeat([]byte{byte(i)}, i)...), nil

	}
}

// The block cipher must be padded, because the size of the block cipher
// must be the multiple of the 16 bytes (key size for AES)
func PKCS5Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

// Trimming is the inverse of PKCS5Padding
func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func decryptChunk(enc_chunk []byte, key []byte, iv []byte) []byte {

	if len(enc_chunk)%aes.BlockSize != 0 {
		panic("cipherTextByte is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	plaintext := make([]byte, len(enc_chunk))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, enc_chunk)

	beforePad := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		beforePad[i] = plaintext[i]
	}

	plaintextUnpadded, err := pkcs7strip(beforePad, block.BlockSize())
	if err != nil {
		fmt.Println("Unpadding error1", err)
	}

	return plaintextUnpadded

}

func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func pkcs7_padding_data_length(buffer []byte, buffer_size byte, modulus byte) (byte, error) {
	if buffer_size%modulus != 0 || buffer_size < modulus {
		fmt.Println("buffer_size 1 error")
		return 0, fmt.Errorf("buffer_size 1 error\n")
	}
	var padding_value byte
	padding_value = buffer[buffer_size-1]

	/* test for valid padding value */

	// fmt.Printf("Decrypted part : %x\n", buffer)

	if padding_value < 1 || padding_value > modulus {
		fmt.Printf("padding_value 2 error %d\n", padding_value)
		return 0, fmt.Errorf("padding_value 2 error %x\n", padding_value)
	}
	/* buffer must be at least padding_value + 1 in size */
	if buffer_size < padding_value+1 {
		fmt.Println("buffer_size 2 error")
		return 0, fmt.Errorf("buffer_size 3 error\n")
	}

	buffer_size--

	for count := 1; count < int(padding_value); count++ {
		buffer_size--
		if buffer[buffer_size] != padding_value {
			fmt.Println("buffer_size 4 error")
			return 0, fmt.Errorf("buffer_size 4 error\n")
		}
	}
	return buffer_size, nil

}

func pkcs7_padding_pad_buffer(buffer []byte, data_length byte, buffer_size byte, modulus byte) (byte, error) {

	pad_byte := modulus - (data_length % modulus)
	if data_length+pad_byte > buffer_size {
		return -pad_byte, fmt.Errorf("padding_value 1 error %x\n", pad_byte)
	}

	i := 0

	for i = 0; i < int(pad_byte); i++ {
		buffer[data_length+byte(i)] = pad_byte
	}

	return pad_byte, nil
}

func PKCS7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func encodeChunk(c Chunk, key []byte, iv []byte) EncryptedChunk {

	c_local := make([]byte, len(c))

	for i := 0; i < len(c); i++ {
		c_local[i] = c[i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cp, err := pkcs7pad(c_local, block.BlockSize())
	if err != nil {
		fmt.Println("Padding error1", err)
	}

	// fmt.Printf("Padded : %x\n", cp)

	ciphertext := make([]byte, len(cp))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, cp)

	return ciphertext

}

// Creation of AES parameters from a chunk's hash (H): Key and IV
// Key = H[0...15]
// IV = H[16...31]
func createKeyandIV(h Hash) (Key, IV) {

	key := Key(h[:16])
	iv := IV(h[16:32])

	return key, iv
}

// Creation of Obfuscation X parameter (64 bytes) from a chunks' hash (H)
// X_n = H_n-1 | H_n-2
func createXelement(h_1 Hash, h_2 Hash) Xelement {

	X_1 := Xelement(h_1)
	X_2 := Xelement(h_2)

	X := append(X_1, X_2...)

	// fmt.Printf("X element %x \n", X)
	return X
}

// Creation of Obfuscation X parameter (64 bytes) from a chunks' hash (H)
// H_512(H_256(C_i-1 | R_i-1 )
func createXelementImproved(h Hash) Xelement {

	X := computeHashSHA_512(Chunk(h))

	// fmt.Printf("X element %x \n", X)
	return Xelement(X)
}

// Create a Tab of X elements for the Obfuscation "encoding"
// X_n = H_n-1 | H_n-2
func (x_tab *Xelement_Tab) CreateXelement_Tab(h_tab Hash_Tab) {
	numOfHashElements := h_tab.Num_Hash_Tab_Elements

	hash_array := make([]Hash, numOfHashElements)

	for i, hash := range h_tab.Hash_Tab_Elements {
		hash_array[i] = hash
	}

	for i := 0; i < numOfHashElements; i++ {

		X := make(Xelement, 0)

		if i == 0 {
			X = createXelement(hash_array[numOfHashElements-1], hash_array[numOfHashElements-2])
		} else if i == 1 {
			X = createXelement(hash_array[0], hash_array[numOfHashElements-1])
		} else {
			X = createXelement(hash_array[i-1], hash_array[i-2])
		}
		x_tab.Xelement_Tab_Elements = append(x_tab.Xelement_Tab_Elements, X)
		// fmt.Printf("Xelement %x  Hash %x\n", x_tab.Xelement_Tab_Elements[i], hash_array[i])
		x_tab.IncrNumElements()

	}

}

// Create a Tab of X elements for the Obfuscation "encoding"
// X_n = H_512(H_256(C_i-1 | R_i-1 )
func (x_tab *Xelement_Tab) CreateXelement_Tab_Improved(h_tab Hash_Tab) {
	numOfHashElements := h_tab.Num_Hash_Tab_Elements

	hash_array := make([]Hash, numOfHashElements)

	for i, hash := range h_tab.Hash_Tab_Elements {
		hash_array[i] = hash
	}

	for i := 0; i < numOfHashElements; i++ {

		X := make(Xelement, 0)

		if i == 0 {
			// X = createXelementImproved(hash_array[numOfHashElements-1])
			X = Xelement(hash_array[numOfHashElements-1])
		} else {
			// X = createXelementImproved(hash_array[i-1])
			X = Xelement(hash_array[i-1])
		}
		x_tab.Xelement_Tab_Elements = append(x_tab.Xelement_Tab_Elements, X)
		// fmt.Printf("Xelement %x  Hash %x\n", x_tab.Xelement_Tab_Elements[i], hash_array[i])
		x_tab.IncrNumElements()

	}

}

func XoR(X Xelement, E EncryptedChunk) []byte {

	X_len := len(X)
	E_len := len(E)

	len_diff := E_len - X_len

	k := E_len / X_len
	t := E_len - (k * X_len)

	// fmt.Printf("cap %v, len %v\n", cap(X), len(X))

	X_to_xor := make(Xelement, 0)

	// fmt.Printf("Thor X_len %d, E_len %d len_diff %d\n", X_len, E_len, len_diff)

	// fmt.Printf("Ant man k len %d\n", k)

	if len_diff != 0 && len_diff > 0 {
		for i := 0; i < k; i++ {
			X_to_xor = append(X_to_xor, X...)
		}

		// fmt.Printf("Iron Man X_len %d\n", len(X_to_xor))

		X_tmp := X[:t]

		X_to_xor = append(X_to_xor, X_tmp...)
		// fmt.Printf("Tony Stark X_len %d\n", len(X_to_xor))

	} else if len_diff == 0 {
		X_to_xor = X
	} else {

		X_to_xor = append(X_to_xor, X[:E_len]...)
	}

	res := make([]byte, E_len)

	for i := 0; i < E_len; i++ {
		res[i] = E[i] ^ X_to_xor[i]

	}

	// fmt.Println("Agent Romanov")

	return res

}

// Creation of a Tab containing the key and iv values
// the values are created according to the Hash Tab and as many
// values as the number of chunks (or hashes)
// Key_n =  H_n-1[0...15],		Key_n-1 =  H_n-2[0...15]
// IV_n = H_n-1[16...31],		IV_n-1 = H_n-2[16...31]
// wnen n=0 -> uses H_n for Key_0 and H_0

func (key_iv_tab *Key_IV_Tab) CreateKeyandIV_Tab(h_tab Hash_Tab) {

	numOfHashElements := h_tab.Num_Hash_Tab_Elements

	hash_array := make([]Hash, numOfHashElements)

	for i, hash := range h_tab.Hash_Tab_Elements {
		hash_array[i] = hash
	}

	for i := 0; i < numOfHashElements; i++ {

		key := make(Key, 0)
		iv := make(IV, 0)

		if i == 0 {
			key, iv = createKeyandIV(hash_array[numOfHashElements-1])
		} else {
			key, iv = createKeyandIV(hash_array[i-1])
		}

		key_iv_tab.Key_Elements = append(key_iv_tab.Key_Elements, key)
		key_iv_tab.IV_Elements = append(key_iv_tab.IV_Elements, iv)
		key_iv_tab.IncrNumElements()
	}

}

// First Level encryption, the Hah values of the Chunks are used as Key and IV for the AES block cipher
// The function encodes all of the chunks using the AES block cipher -> return a Tab of encrpyted chunks
// AES ( Key, IV )  ->  Key_n =  H_n-1[0...15],		Key_n-1 =  H_n-2[0...15]
//
//	IV_n = H_n-1[16...31],		IV_n-1 = H_n-2[16...31]
func (enc_tab *EncryptedChunk_Tab) CreateEncryptedChunkTab(c_tab Chunk_Tab, h_tab Hash_Tab) {

	var key_iv_tab Key_IV_Tab

	key_iv_tab.CreateKeyandIV_Tab(h_tab)
	// fmt.Printf("*********** In CreateEncryptedChunkTab *********** \n ")

	for i, chunk := range c_tab.Chunk_Tab_Elements {

		encrypted_chunk := encodeChunk(chunk, key_iv_tab.Key_Elements[i], key_iv_tab.IV_Elements[i])

		enc_tab.EncryptedChunk_Tab_Elements = append(enc_tab.EncryptedChunk_Tab_Elements, encrypted_chunk)
		enc_tab.IncrNumElements()
		// plaintextUnpadded := decryptChunk(encrypted_chunk, key_iv_tab.Key_Elements[i], key_iv_tab.IV_Elements[i])
		// fmt.Printf("Plaintext : %x\n", plaintextUnpadded)
	}
}

// Second Level encryption is the Obfuscation of the "AES encoded" chunks => result of CreateEncryptedChunkTab(...) are retrived
// in order to apply the obfuscation which is the X xor Encryptrd chunks ( EX = X xor E )
func (enc_tab *EncryptedChunk_Tab) CreateSecondLevel_EncryptedChunkTab(X_tab Xelement_Tab) {

	for i, X := range X_tab.Xelement_Tab_Elements {
		// fmt.Printf("cap %v, len %v\n", cap(X), len(X))
		// fmt.Printf("XoR 1: %x\n", enc_tab.EncryptedChunk_Tab_Elements[i])

		EX := XoR(X, enc_tab.EncryptedChunk_Tab_Elements[i])

		// fmt.Printf("XoR 1 bis: %x\n", EX)

		enc_tab.EncryptedChunk_SecondLevel_Tab_Elements = append(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements, EX)
		enc_tab.IncrNumElementsSecondLevel()

		// fmt.Printf("XoR 1: %x\n", enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[i])

	}
}

// First Level decryption, the Chunks of Tab of encrpyted chunks are decrypted thanks to the Key and VI
// AES ( Key, IV )  ->  Key_n =  H_n-1[0...15],		Key_n-1 =  H_n-2[0...15]
//
//	IV_n = H_n-1[16...31],		IV_n-1 = H_n-2[16...31]
func (dec_tab *DecryptedChunk_Tab) CreateDecryptedChunkTab(enc_tab EncryptedChunk_Tab, h_tab Hash_Tab) {

	var key_iv_tab Key_IV_Tab

	key_iv_tab.CreateKeyandIV_Tab(h_tab)

	for i, encrypted_chunk := range enc_tab.EncryptedChunk_Tab_Elements {
		decrypted_chunk := decryptChunk(encrypted_chunk, key_iv_tab.Key_Elements[i], key_iv_tab.IV_Elements[i])
		// fmt.Printf("decrypted_chunk : %s \n", string(decrypted_chunk))
		dec_tab.DecryptedChunk_Tab_Elements = append(dec_tab.DecryptedChunk_Tab_Elements, decrypted_chunk)
		dec_tab.IncrNumElements()
	}
}

// First Level decryption, the Chunks of Tab of encrpyted chunks are decrypted thanks to the Key and VI
// In this version the DecryptedChunk_Tab second level decrypted chunks can be used as input to obtain
// the first level decrypted chunks
// AES ( Key, IV )  ->  Key_n =  H_n-1[0...15],		Key_n-1 =  H_n-2[0...15]
//
//	IV_n = H_n-1[16...31],		IV_n-1 = H_n-2[16...31]
func (dec_tab *DecryptedChunk_Tab) CreateDecryptedChunkTabImproved(h_tab Hash_Tab) {

	var key_iv_tab Key_IV_Tab

	key_iv_tab.CreateKeyandIV_Tab(h_tab)

	for i, encrypted_chunk := range dec_tab.DecryptedChunk_SecondLevel_Tab_Elements {
		decrypted_chunk := decryptChunk(EncryptedChunk(encrypted_chunk), key_iv_tab.Key_Elements[i], key_iv_tab.IV_Elements[i])

		dec_tab.DecryptedChunk_Tab_Elements = append(dec_tab.DecryptedChunk_Tab_Elements, decrypted_chunk)
		dec_tab.IncrNumElements()
		dec_tab.IncTotalSize(len(decrypted_chunk))
	}
}

// Second Level decryption is the Obfuscation of the Second Level encrypted chunks are retrived from
// EncryptedChunk_SecondLevel_Tab_Elements of EncryptedChunk_SecondLevel_Tab_Elements
// in order to apply the obfuscation which is the X xor Encryptrd chunks ( EX = X xor E )
func (dec_tab *DecryptedChunk_Tab) CreateSecondLevel_DecryptedChunkTab(enc_tab EncryptedChunk_Tab, X_tab Xelement_Tab) {
	// fmt.Println("///////// CreateSecondLevel_DecryptedChunkTab //////")

	for i, secondLevelEncChunk := range enc_tab.EncryptedChunk_SecondLevel_Tab_Elements {
		secondLevelDecrypted_chunk := XoR(X_tab.Xelement_Tab_Elements[i], secondLevelEncChunk)

		dec_tab.DecryptedChunk_SecondLevel_Tab_Elements = append(dec_tab.DecryptedChunk_SecondLevel_Tab_Elements, secondLevelDecrypted_chunk)
	}

}

func (dec_tab *DecryptedChunk_Tab) WriteCertificateAndSignatureFile(directoryOfIdentity string, identityName string,
	directoryOfSignature string, signatureName string, signatureExtention string) {

	lastChunkJSON := dec_tab.DecryptedChunk_Tab_Elements[dec_tab.Num_DecryptedChunk_Tab_Elements-1]

	var lastChunk LastChunk
	err := json.Unmarshal(lastChunkJSON, &lastChunk)
	if err != nil {
		panic(err)
	}

	identityNameWithExtetnion := identityName + ".pem"
	WriteData([]byte(lastChunk.Identitiy), directoryOfIdentity, identityNameWithExtetnion)

	signatureNameWithExtetnion := signatureName + "." + signatureExtention
	WriteData([]byte(lastChunk.Signature), directoryOfSignature, signatureNameWithExtetnion)

}

// // Second Level encryption is the Obfuscation of the "AES encoded" chunks => result of CreateEncryptedChunkTab(...) are retrived
// // in order to apply the obfuscation which is the X xor Encryptrd chunks ( EX = X xor E )
// func (enc_tab *EncryptedChunk_Tab) CreateSecondLevel_EncryptedChunkTab (X_tab Xelement_Tab) {

func (h_enc *Hash_Encrypted_Tab) CreateHash_Encrypted_Tab(enc_tab EncryptedChunk_Tab) {

	for _, enc_chunk := range enc_tab.EncryptedChunk_SecondLevel_Tab_Elements {
		hash := computeHash(Chunk(enc_chunk))
		h_enc.Hash_Encrypted_Tab_Elements = append(h_enc.Hash_Encrypted_Tab_Elements, hash)
		h_enc.IncrNumElements()
		// fmt.Printf("Hash of second level encrypted chunk: %x \n",hash)
	}
}

type LastChunk struct {
	Identitiy string
	Signature string
}

// This function create a chunk for the Identity (cert.pem) and a signature over the Identity
// The Identity is the users certification cert.pem
// The created chunk os alsways the last chunk of the chunk tab that contains this information
// The ECDSA signature scheme is used to sign the Identity
func (tabOfChunks *Chunk_Tab) AddIdentityAndSignatureChunk(directoryOfID string, nameOfID string,
	directoryOfPrivKey string, nameOfPrivKey string) {
	// "./data/test2/MSP/signcerts", "cert", "pem"
	identity, _ := ReadData(directoryOfID, nameOfID, "pem")

	//"./data/test2/MSP/keystore", "sk"

	raw, _ := ReadData(directoryOfPrivKey, nameOfPrivKey, "pem")
	block, rest := pem.Decode(raw)
	if block == nil {
		fmt.Println("Problem ", rest)
	}
	// fmt.Println("Block : ", block )
	// privateKey := parsePrivateKey(block.Bytes)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Problem ", rest)
	}
	privateKey := key.(*ecdsa.PrivateKey)

	hash := sha256.Sum256(identity)

	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		panic(err)
	}
	// fmt.Printf("signature: %x\n", sig)

	lastChunk := LastChunk{Identitiy: string(identity), Signature: hex.EncodeToString(sig)}

	identityWithSignatureJSON, _ := json.Marshal(lastChunk)
	// fmt.Println("JSON : ", string(identityWithSignatureJSON))

	tabOfChunks.Chunk_Tab_Elements = append(tabOfChunks.Chunk_Tab_Elements, identityWithSignatureJSON)
	tabOfChunks.IncrNumElements()

	// valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], sig)
	// fmt.Println("signature verified:", valid)

}

// Self Encrypton of the data, parameters:
// inputDirectory: directory in which the data is
// nameOfData: the data name (file name)
// extentionOfData: extention of the data (e.g., .pdf)
// numbertOfChunks: desired number of data chunk (data is devided into equal data chunks)
// extentionOfChunks: extention of the data chuks
// outputDirectoryEncryption: the directory of the encrypted data chunks
// outputDirectoryKeys: the directory of the keys generated for the encryption/decryption
// extentionOfKeys: extention of the keys (e.g., .o)
// produceWriteValues: produce write values to the directories, in certain cases it is not
// inputDirectoryOfIdentitiy directory in which the Identity is
// nameOfIdentity: name of the Identity (file name) by default its extentions is .pem
// inputDirectoryOfPrivateKey: directory of the private key, needed to sign the Identity
// nameOfPrivateKey: name of the Private Key (file name) by default its extentions is .pem
// necessary to write the data into files (depends on the application, use case)

func SelfEncryptData(inputDirectory string, nameOfData string, extentionOfData string,
	numbertOfChunks int, extentionOfChunks string, outputDirectoryEncryption string,
	outputDirectoryKeys string, extentionOfKeys string, outputDirectoryRefs string,
	inputDirectoryOfIdentitiy string, nameOfIdentity string, inputDirectoryOfPrivateKey string,
	nameOfPrivateKey string, produceWriteValues bool) (EncryptedChunk_Tab, Hash_Tab, Hash_Tab) {

	// fmt.Println("//////////////////////////////////////////////////////////////////")
	// fmt.Println("                Information about Self-Encryption")
	// fmt.Println(" Input directory of data: ", inputDirectory)
	// fmt.Println(" Data name : ", nameOfData)
	// fmt.Println(" Extension of data : ", extentionOfData)
	// fmt.Println(" Desired number of data chunks  : ", numbertOfChunks)
	// fmt.Println(" Extension of chunks  : ", extentionOfChunks)
	// fmt.Println(" Output directory of data : ", outputDirectoryEncryption)
	// fmt.Println(" Output directory of Keys : ", outputDirectoryKeys)
	// fmt.Println(" Output directory of References : ", outputDirectoryRefs)
	// fmt.Println(S" Extension of keys : ", extentionOfKeys)
	// fmt.Println(" Input directory of Identity: ", inputDirectoryOfIdentitiy)
	// fmt.Println(" Identity name : ", nameOfIdentity)
	// fmt.Println(" Input directory of Private Key: ", inputDirectoryOfPrivateKey)
	// fmt.Println(" Private Key name : ", nameOfPrivateKey)
	// fmt.Println(" Produce write vaues to directories : ", produceWriteValues)

	data, lengthOfData := ReadData(inputDirectory, nameOfData, extentionOfData)

	// fmt.Println(" Lenght of data : ", lengthOfData, "Bytes")
	// fmt.Println("//////////////////////////////////////////////////////////////////")

	// fmt.Printf("Original data : %x\n", data)
	// dataTab, numbertOfChunks := BeOTP(data, lengthOfData)

	dataTab := CreateDataChunksChunkType(data, lengthOfData, numbertOfChunks)

	var tabOfChunks Chunk_Tab

	tabOfChunks.Chunk_Tab_Elements = make([]Chunk, numbertOfChunks)
	tabOfChunks.Num_Chunk_Tab_Elements = numbertOfChunks

	for i := 0; i < numbertOfChunks; i++ {
		tabOfChunks.Chunk_Tab_Elements[i] = Chunk(string(dataTab[i]))
	}

	// Add a chunk containing the Identity and the signature on the Identity
	tabOfChunks.AddIdentityAndSignatureChunk(inputDirectoryOfIdentitiy, nameOfIdentity, inputDirectoryOfPrivateKey, nameOfPrivateKey)
	numbertOfChunks++

	var tabOfHash Hash_Tab

	tabOfHash.CreateHahsTabWithRand(tabOfChunks)

	if produceWriteValues == true {
		WriteKeys(tabOfHash, numbertOfChunks, outputDirectoryKeys, extentionOfKeys)
	}

	/////////////////////////////////// 1st Level Encryption /////////////////////////////
	var enc_tab EncryptedChunk_Tab
	enc_tab.CreateEncryptedChunkTab(tabOfChunks, tabOfHash)
	//////////////////////////////////////////////////////////////////////////////////////

	///////////////////////////////// XoR TAB for 2nd Level Encryption ///////////////////////////
	var x_tab Xelement_Tab
	x_tab.CreateXelement_Tab_Improved(tabOfHash)
	// x_tab.CreateXelement_Tab(tabOfHash)
	/////////////////////////////////////////////////////////////////////////////////////////////

	//////////////////////////////////////////// 2nd Levle Encryption //////////////////////////////////////
	enc_tab.CreateSecondLevel_EncryptedChunkTab(x_tab)
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// res_tmp := ReadKeys(outputDirectoryKeys)
	// fmt.Printf("Hash : %x\n", res_tmp[0])
	if produceWriteValues == true {
		WriteChunksTypeEncryptedChunk(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements, numbertOfChunks, outputDirectoryEncryption, nameOfData, extentionOfChunks)
	}

	/////////////////////// Create hash tab for the encrypted data chunks ///////////////////////

	var tabOfEXhash Hash_Tab
	tabOfEXhash.CreateHahsTabForEncryptedChunk(enc_tab)

	if produceWriteValues == true {
		WriteRefs(tabOfHash, outputDirectoryRefs)
	}
	////////////////////////////////////////////////////////////////////////////////////////////

	// return enc_tab.EncryptedChunk_SecondLevel_Tab_Elements[1]
	return enc_tab, tabOfHash, tabOfEXhash

}

// Self Decrypton of the data, parameters:
// inputDirectory: directory in which the encrypted data chunks can be found
// nameOfData: the data name (file name) after decryption and conctentation of decrypted data chunks
// extentionOfData: extention of the data (e.g., .pdf)
// outputDirectoryDecryption: the directory of the decrypted data, the chunks are concatenated, it is the
// initial data which is the result
// InputDirectoryKeys: the directory of the keys generated for the encryption/decryption
// outputDirectoryID : the directory of the decrypted Identity
// outputDirectorySignature : the directory of the decrypted Signature
// nameOfIdentity: the name of the Identity (file name) -> the extention of the Identity is .pem by default
// nameOfSignature: the name of the Signature (file name) -> the extention of the signature is .txt by default

func SelfDecryptData(inputDirectory string, nameOfData string, extentionOfData string, outputDirectoryDecryption string,
	InputDirectoryKeys string, outputDirectoryID string, nameOfIdentity string, outputDirectorySignature string, nameOfSignature string) []byte {

	fmt.Println("//////////////////////////////////////////////////////////////////")
	fmt.Println("                Information about Self-Decryption")
	fmt.Println(" Input directory of data chuks: ", inputDirectory)
	fmt.Println(" Data name : ", nameOfData)
	fmt.Println(" Identity name : ", nameOfIdentity)
	fmt.Println(" Signature name : ", nameOfSignature)
	fmt.Println(" Extension of data : ", extentionOfData)
	fmt.Println(" Output directory of the decrypted data : ", outputDirectoryDecryption)
	fmt.Println(" Inout directory of Keys : ", InputDirectoryKeys)
	fmt.Println(" Output directory of the decrypted identity : ", outputDirectoryID)
	fmt.Println(" Output directory of the decrypted Signature : ", outputDirectorySignature)
	fmt.Println("//////////////////////////////////////////////////////////////////")

	// Read the encrypted chunks under inputDirectory
	// Create a tab of encrypted chunks
	encodedChunksToRead := ReadDataChunks(inputDirectory)

	var enc_tab EncryptedChunk_Tab

	for _, encrypted_chunk_2nd := range encodedChunksToRead {

		enc_tab.EncryptedChunk_SecondLevel_Tab_Elements = append(enc_tab.EncryptedChunk_SecondLevel_Tab_Elements, encrypted_chunk_2nd)
		enc_tab.IncrNumElementsSecondLevel()
	}

	// Read keys under InputDirectoryKeys
	// Create a tab with the keys (hashes of the data chunks)

	key_tab := ReadKeys(InputDirectoryKeys)
	var tabOfHash Hash_Tab

	for _, key := range key_tab {
		tabOfHash.Hash_Tab_Elements = append(tabOfHash.Hash_Tab_Elements, key)
		tabOfHash.IncrNumElements()
	}

	// Create X elements for seconf level decryption
	var x_tab Xelement_Tab
	x_tab.CreateXelement_Tab_Improved(tabOfHash)
	// x_tab.CreateXelement_Tab(tabOfHash)

	// Create decryption tab
	var dec_tab DecryptedChunk_Tab

	// Second Level DecryptionCreateSecondLevel_DecryptedChunkTab
	dec_tab.CreateSecondLevel_DecryptedChunkTab(enc_tab, x_tab)

	// First Level Decryption
	dec_tab.CreateDecryptedChunkTabImproved(tabOfHash)

	intitialData := CreateFinalFileFromDecryptedChunk_Tab_When_ID(dec_tab)

	dataNameWithExtention := nameOfData + "." + extentionOfData
	WriteData(intitialData, outputDirectoryDecryption, dataNameWithExtention)

	// dec_tab.WriteCertificateAndSignatureFile(outputDirectoryID, nameOfIdentity, outputDirectorySignature, nameOfSignature, "txt")

	return dec_tab.DecryptedChunk_SecondLevel_Tab_Elements[1]

}

func MyCompare(input1 []byte, input2 []byte) {
	fmt.Println("////////////////// myCompare /////////////////////////")
	res := bytes.Compare(input1, input2)
	if res == 0 {
		fmt.Println("!..Slices are equal..!")
	} else {
		fmt.Println("!..Slice are not equal..!")
	}
	fmt.Println("///////////////////////////////////////////////////////")

}
