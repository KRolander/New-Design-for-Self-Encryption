//  Copyright (c) 2022 TU Delft - IRIS project. All rights reserved.
// Author: Roland Kromes - R.G.Kromes@tudelft.nl

package tools

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// type DataChunk []byte

// type DataChunks struct {
// 	Chunk []DataChunk
// 	NumOfChunks int
// }

// func New () DataChunks {
// 	return DataChunks{}
// }

// Read all of the chunks contained by the given directory "directory"
func ReadDataChunks(directory string) [][]byte {
	// fmt.Println("In ReadDataChunks; elements in the directory:")
	files, err := ioutil.ReadDir(directory)
	check(err)

	var data [][]byte
	data = make([][]byte, 0, 0)

	var newFileName string

	for i, f := range files {
		fileName := f.Name()

		if strings.Contains(fileName, ".") {
			separatefileName := strings.Split(fileName, ".")

			withoutPoint := separatefileName[0]
			fileExt := separatefileName[1]
			separateAgainfileName := strings.Split(withoutPoint, "_")

			newFileName = separateAgainfileName[0] + "_" + strconv.Itoa(i) + "." + fileExt

		} else if strings.Contains(fileName, ".") == false {
			separateAgainfileName := strings.Split(fileName, "_")
			newFileName = separateAgainfileName[0] + "_" + strconv.Itoa(i)
		} else {
			fmt.Println("Error while ordering file names")
			os.Exit(1)
		}

		fmt.Println(newFileName)

		data_tmp, _ := ReadData(directory, newFileName, "")

		data = append(data, data_tmp)
		check(err)

	}

	return data
}

// Read all of the Keys contained by the given directory "directory"
func ReadKeys(directory string) [][]byte {
	files, err := ioutil.ReadDir(directory)
	check(err)

	var data [][]byte
	data = make([][]byte, 0, 0)

	var newFileName string

	for i, f := range files {
		fileName := f.Name()

		if strings.Contains(fileName, ".") {
			separatefileName := strings.Split(fileName, ".")

			withoutPoint := separatefileName[0]
			fileExt := separatefileName[1]
			separateAgainfileName := strings.Split(withoutPoint, "_")

			newFileName = separateAgainfileName[0] + "_" + strconv.Itoa(i) + "." + fileExt

		} else if strings.Contains(fileName, ".") == false {
			separateAgainfileName := strings.Split(fileName, "_")
			newFileName = separateAgainfileName[0] + "_" + strconv.Itoa(i)
		} else {
			fmt.Println("Error while ordering file names")
			os.Exit(1)
		}

		fmt.Println(newFileName)

		data_tmp, _ := ReadData(directory, newFileName, "")

		data = append(data, data_tmp)
		check(err)

	}

	return data
}

// Read the data from the file called "fileName" with its extention ("fileExtentsion") at the path called "directory"
func ReadData(directory string, fileName string, fileExtension string) ([]byte, int) {
	var fileToRead string
	if fileExtension == "" {
		fileToRead = directory + "/" + fileName
	} else {
		fileToRead = directory + "/" + fileName + "." + fileExtension
	}

	data, err := os.ReadFile(fileToRead)
	check(err)

	lengthOfData := len(data)

	return data, lengthOfData
}

// Write the given "data" to the given "directory", the name of the file is given
// by "fileName"dataChunks
func WriteData(data []byte, directory string, fileName string) {

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		err := os.Mkdir(directory, 0777)
		check(err)
	}

	fileToWrite := directory + "/" + fileName

	f, err := os.Create(fileToWrite)
	check(err)

	defer f.Close()

	_, err1 := f.Write(data)
	check(err1)
	// err := os.WriteFile(fileToWrite, data, 0666)
	// check(err)
}

// Create chunks in the "directory" path, fileName precises the global name of the chunks
// fileExtension can be any format (e.g., txt, jpg, o), "num" number of chunks to write
func WriteChunks(tabOfChunks [][]byte, num int, directory string, fileName string, fileExtension string) {

	for i := 0; i < num; i++ {
		newFileName := fileName + "_" + strconv.Itoa(i) + "." + fileExtension
		// fmt.Println("File name : ", newFileName)
		WriteData(tabOfChunks[i], directory, newFileName)
	}
}

// Create Keys (chunks' hashes) "directory" path, fileName precises the global name of the chunks
// fileExtension can be any format (e.g., txt, jpg, o), "num" number of chunks to write
func WriteKeys(tabOfHash Hash_Tab, num int, directory string, fileExtension string) {

	for i := 0; i < num; i++ {
		newFileName := "Key_" + strconv.Itoa(i) + "." + fileExtension
		// fmt.Println("File name : ", newFileName)
		WriteData(tabOfHash.Hash_Tab_Elements[i], directory, newFileName)
	}
}

// Create a file with the encrypted data chunk hashes (references to the encrypted data chuks)
// "directory" path, fileName is the name of the file
func WriteRefs(tabOfHash Hash_Tab, directory string) {

	fileToWrite := directory + "/References.txt"

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		err := os.Mkdir(directory, 0777)
		check(err)
	}

	f, err := os.Create(fileToWrite)
	check(err)

	defer f.Close()

	for i := 0; i < tabOfHash.Num_Hash_Tab_Elements; i++ {

		_, err := f.WriteString("Ref_" + strconv.Itoa(i) + ":" + hex.EncodeToString(tabOfHash.Hash_Tab_Elements[i]) + "\n")
		check(err)
	}
}

// Create chunks in the "directory" path, fileName precises the global name of the chunks
// fileExtension can be any format (e.g., txt, jpg, o), "num" number of chunks to write
// The input type is "[]EncryptedChunk" used by the structure EncryptedChunk_Tab
func WriteChunksTypeEncryptedChunk(tabOfChunks []EncryptedChunk, num int, directory string, fileName string, fileExtension string) {

	for i := 0; i < num; i++ {
		newFileName := fileName + "_" + strconv.Itoa(i) + "." + fileExtension
		// fmt.Println("File name : ", newFileName)
		WriteData(tabOfChunks[i], directory, newFileName)
	}
}

// func CreateFinalFile(chunkTab ...[]byte) []byte{

// 	res := []byte{}
// 	for _, chunk := range chunkTab {
// 		res = append(res, chunk...)
// 	}
// 	// fmt.Println(res)
// 	return res
// }

// "chunkTab" is a Tab of all of the chunks which are concatenated
// to obtain the final data (only one file)
func CreateFinalFile(chunkTab [][]byte) []byte {

	res := []byte{}
	for _, chunk := range chunkTab {
		res = append(res, chunk...)
	}
	// fmt.Println(res)
	return res
}

// "chunkTab" is a Tab of all of the chunks which are concatenated
// to obtain the final data (only one file)
func CreateFinalFileFromDecryptedChunk_Tab_When_ID(dec_tab DecryptedChunk_Tab) []byte {
	// var totalLen int

	// for _, s := range dec_tab.DecryptedChunk_Tab_Elements {
	//     totalLen += len(s)
	// }

	num := dec_tab.Num_DecryptedChunk_Tab_Elements

	originalDataSize := dec_tab.totalSize - len(dec_tab.DecryptedChunk_Tab_Elements[num-1])

	tmp := make([]byte, originalDataSize)

	fmt.Printf("Size : %d originalDatasize : %d, totalSize : %d\n", len(dec_tab.DecryptedChunk_Tab_Elements[num-1]), originalDataSize, dec_tab.totalSize)

	var i int
	for _, s := range dec_tab.DecryptedChunk_Tab_Elements[:num-1] {
		i += copy(tmp[i:], s)
	}

	return tmp
}

func CreateFinalFileFromDecryptedChunk_Tab(dec_tab DecryptedChunk_Tab) []byte {

	num := dec_tab.Num_DecryptedChunk_Tab_Elements

	tmp := make([]byte, dec_tab.totalSize)

	var i int
	for _, s := range dec_tab.DecryptedChunk_Tab_Elements[:num] {
		i += copy(tmp[i:], s)
	}

	fmt.Printf("Final chunks : %x\n", tmp)
	return tmp
}

// Creation of "num" data chunks of equal size
// "tabToCopy" is the input data to be divided into chunks
func CreateDataChunks(tabToCopy []byte, lengthOfData int, num int) [][]byte {
	// fmt.Printf("Hello World from CreateDataChunks()!")

	lenData := lengthOfData
	dif := 0

	tab := make([][]byte, 0, num)

	k := 0
	l := 0
	j := 0
	for i := num; i > 0; i-- {
		dif = lenData / i
		lenData = lenData - dif

		j = dif + l
		tab[k] = tabToCopy[l:j]
		l = j

		k++

	}
	return tab
}

func BeOTP(tabToCopy []byte, lengthOfData int) ([]Chunk, int) {

	lenData := lengthOfData/48 + 1

	tab := make([]Chunk, lenData)
	l := 0
	j := 0
	for i := 0; i < lenData-1; i++ {
		j = l + 48
		tab[i] = tabToCopy[l:j]

		l = l + 48
	}
	tab[lenData-1] = tabToCopy[j:]

	return tab, lenData
}

// Creation of "num" data chunks of equal size
// "tabToCopy" is the input data to be divided into chunks
func CreateDataChunksChunkType(tabToCopy []byte, lengthOfData int, num int) []Chunk {

	lenData := lengthOfData
	dif := 0

	tab := make([]Chunk, num)

	k := 0
	l := 0
	j := 0
	for i := num; i > 0; i-- {
		dif = lenData / i
		lenData = lenData - dif

		j = dif + l
		tab[k] = tabToCopy[l:j]
		l = j

		k++

	}
	return tab
}

func Hello() {
	fmt.Printf("Hello World ! \n")
}
