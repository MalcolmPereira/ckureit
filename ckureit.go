// Package main for ckureit utility
package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/malcolmpereira/ckureit/crypto"
)

//ckureitUsage contains static text for ckureit utility usage
const ckureitUsage = `
	Missing Program Arguments. Please use ckureit as follows: 
	
	File Encryption: 
	
					ckureit -s <secret text 10-22 chars> -f <file to be encrypted> 
	
	This creates encrypted file named " + time.Now().Format(timeStampFormat) + encryptedFileExt + " in current directory.
	
	File Decryption: 
	
					ckureit -s <secret text 10-22 chars> -f <file to be decrypted> -d <decryption key> 
	
	This reads encrypted and decrypts file into current directory.
	
`

//Main entry point for the ckureit utility
//Command line takes the following flags
// -s secret used to encrypt/decrypt file (required)
// -f file name to be encrypted/decrypted (required)
// -d decryption key to decrypt file (required for decryption)
func main() {

	secretPtr := flag.String("s", "", "Required - Secret used to encrypt/decrypt, 10-22 chars.")
	fileNamePtr := flag.String("f", "", "Required - File to be encrypted/decrypted.")
	decryptPtr := flag.String("d", "", "Decrypt key for file decryption.")

	flag.Parse()

	secretKey := strings.Trim(*secretPtr, " ")
	if len(secretKey) == 0 {
		fmt.Println(usage())
		return
	}
	if len(secretKey) < 10 || len(secretKey) > 22 {
		fmt.Println(usage())
		return
	}

	fileName := strings.Trim(*fileNamePtr, " ")
	if len(fileName) == 0 {
		fmt.Println(usage())
		return
	}

	decryptKey := strings.Trim(*decryptPtr, " ")

	var encryptedFile string
	var result string
	var err error
	if len(decryptKey) == 0 {
		encryptedFile, result, err = crypto.Encrypt(secretKey, fileName) //Encryption
	} else {
		result, err = crypto.Decrypt(secretKey, fileName, decryptKey) //Decryption
	}

	if err != nil {
		fmt.Println("Error processing request", err)
		return
	}

	if len(decryptKey) == 0 {
		fmt.Println("Completed Ecryption, Encrypted File: "+encryptedFile+", Required Decryption Key : ", result)
	} else {
		fmt.Println("Completed Decryption File: ", result)
	}
}

//Usage returns string that prints usage for ckureit utility
func usage() string {
	return ckureitUsage
}
