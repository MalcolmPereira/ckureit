// Package crypto for ckureit utility which performs AES-256 encryption of a given file
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//secretkeylength length for AES-256 secret
const secretkeylength = 32

//ivkeypre max iv chars taken fron user input
const ivkeypre = 10

//ivkeylength length for AES-256 IV
const ivkeylength = 16

//returnKey lengths these form part of the returned decryption token
const returnkeyPart1 = 2
const returnkeyPart2 = 3

//min max secret chars take fron user input
const secretMin = 10
const secretMax = 22

//space contains the space char that will be trimmed
const whitespace = " "

//nonceString is used to generate random nonce chars
const nonceString = "ABCzDy!ExwvFuGtHs@#IrJqK^pLoMnNmOl$%PkQjRiShTgUfVeWdXcYb&Za123456789*"

//writeKeyToken padding tokens to encrypt part of the dynamically generated nonce with the encrypted file
const writeKeyToken = "[]<>?/;:'?{}|`~1"

//encryptedFileExtension Extension for Encrypted File
const encryptedFileExtension = ".ckureit"

//Encrypt will encrypt file  using the given secret key
//string - Secret Key
//string - File to be encrypted
//Encrypt will return  (encryptedFileName, decryptKey, error)
//encryptedFileName - The encrypted file
//decryptKey - Token needed for decryption
//error - Error for  operation
func Encrypt(secretKeyVal string, fileName string) (string, string, error) {
	var result = ""

	//Validate Secret Key
	key, keyErr := validateSecretKeyLength(secretKeyVal)
	if keyErr != nil {
		return "", "", keyErr
	}

	//Validate File Name
	fileName, fileErr := validateRequired(fileName)
	if fileErr != nil {
		return "", "", fileErr
	}

	//Split Secret Key into parts and also get all unique chars from Secret Key
	key1, key2, uniqueChars := prepareEncryptionKeys(key)

	//Get Randomly generated nonces which will be used for remaining parts for SecretKey and IVKey
	secretKeyRemaining, ivKeyRemaining := getEncryptionKeysRemaining(key1, key2, uniqueChars)

	//Get the return token will be used for decryption
	//and token that will be encryted with the file itself
	//this tokens are unique for every encryption
	returnKey, writeKey := getReturnKeyWriteKey(secretKeyRemaining, ivKeyRemaining)

	//Prepare WriteKeySecret which will be used to encrypt part of the token with the file
	writeKeySecret := string((uniqueChars + returnKey + writeKeyToken)[0:ivkeylength])

	//Encrypted writeKey to be added to encrypted file
	encryptedWriteKey := encryptText(writeKeySecret, writeKey)

	//Get secret which will be used for encryption
	secretKey := getSecretKey(key1, key2, secretKeyRemaining)

	//Get IV which will be used for encryption
	ivKey := getIVKey(uniqueChars, ivKeyRemaining)

	//Encrypt file
	result, err := encryptFile(secretKey, ivKey, writeKeySecret, encryptedWriteKey, fileName)

	if err != nil {
		fmt.Println("Failed processing file encrytion", err)
		return "", "", err
	}

	return result, returnKey, nil
}

//Decrypt will decrypt file using given secret key and the decryption token
//string - Secret Key
//string - File to be decrypted
//string - Decryption token
//Decrypt will return  (fileName, error)
//fileName - Decrypted file
//error - Error for operation
func Decrypt(secretKeyVal string, fileName string, decryptKey string) (string, error) {
	var result = ""

	//Validate Secret Key
	key, keyErr := validateSecretKeyLength(secretKeyVal)
	if keyErr != nil {
		return "", keyErr
	}

	//Validate File Name
	fileName, fileErr := validateRequired(fileName)
	if fileErr != nil {
		return "", fileErr
	}

	//Validate Decrypt Key
	decryptKey, decryptErr := validateRequired(decryptKey)
	if decryptErr != nil {
		return "", decryptErr
	}

	//Split Secret Key into parts and also get all unique chars from Secret Key
	key1, key2, uniqueChars := prepareEncryptionKeys(key)

	//Prepare WriteKeySecret which will be used to decrypt part of token in the file
	writeKeySecret := string((uniqueChars + decryptKey + writeKeyToken)[0:ivkeylength])

	//Get nonces which were encrypted with the file
	//these will be used for remaining parts for SecretKey and IVKey
	secretKeyRemaining, ivKeyRemaining, writeKeySize, err := getEncryptionKeysRemainingFromFile(key1, key2, uniqueChars, writeKeySecret, decryptKey, fileName)
	if err != nil {
		fmt.Println("Failed processing file decryption", err)
		return "", err
	}

	//Get the secret which will be used for decryption
	secretKey := getSecretKey(key1, key2, secretKeyRemaining)

	//Get the iv key which will be used for decryption
	ivKey := getIVKey(uniqueChars, ivKeyRemaining)

	//Decrypt File
	result, err = decryptFile(secretKey, ivKey, writeKeySecret, writeKeySize, fileName)

	if err != nil {
		fmt.Println("Failed processing file decryption", err)
		return "", err
	}

	return result, nil
}

//TrimInput trims entered input
func trimInput(input string) string {
	return strings.Trim(input, whitespace)
}

//ValidateRequired validates required input and return trimmed value for valid input
//or error
func validateRequired(input string) (string, error) {
	inputString := trimInput(input)
	if len(inputString) == 0 {
		return "", errors.New("Invalid Input")
	}
	return inputString, nil
}

//ValidateSecretKeyLength validates secret key for required input and length,
//and returns trimmed value for valid input or error
func validateSecretKeyLength(input string) (string, error) {
	inputString, err := validateRequired(input)
	if err != nil {
		return "", err
	}
	if len(inputString) < secretMin || len(inputString) > secretMax {
		return "", errors.New("Invalid Secret Input, " + string(rune(secretMin)) + " - " + string(rune(secretMax)) + " chars required")
	}
	return inputString, nil
}

//prepareEncryptionKeys returns the keys based on the entered secret
//these preliminary returned keys - key1, key2, key3
//are then used to generate AES secret key and the IV key
func prepareEncryptionKeys(secretKey string) (string, string, string) {
	var key1 = ""
	key1 = string(secretKey[0 : len(secretKey)/2])
	if len(key1) > secretkeylength {
		key1 = string(key1[0:secretkeylength])
	}
	var key2 = ""
	key2 = string(secretKey[len(secretKey)/2:])
	if len(key2) > secretkeylength {
		key2 = string(key2[0:secretkeylength])
	}
	if len(key1+key2) > secretkeylength {
		key1 = string((key1 + key2)[0 : secretkeylength/2])
		key2 = string((key1 + key2)[secretkeylength/2 : secretkeylength])
	}

	var key3 = removeDuplicates(secretKey)
	if len(key3) > ivkeypre {
		key3 = string(key3[0:ivkeypre])
	}
	return key1, key2, key3
}

//RemoveDuplicates removes duplicates chars from the given string str
func removeDuplicates(str string) string {
	var uniqueStr []rune
	for _, ch := range str {
		if !checkExisting(uniqueStr, ch) {
			uniqueStr = append(uniqueStr, ch)
		}
	}
	return string(uniqueStr)
}

//checkExisting is used to check if string chars are unique
//the rune str is compared in the existing rune array uniqueStrArr
//this is to remove duplicates chars when making a unique string
//for IV or secret keys
func checkExisting(uniqueStrArr []rune, str rune) bool {
	for _, a := range uniqueStrArr {
		if a == str {
			return true
		}
	}
	return false
}

//getRemaning is used to generate random nonce for the given length
func getRemaning(str string, size int) string {
	var remainStr []rune
	inputString := []rune(str)
	for _, ch := range nonceString {
		if !checkExisting(inputString, ch) {
			remainStr = append(remainStr, ch)
		}
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(remainStr), func(i, j int) { remainStr[i], remainStr[j] = remainStr[j], remainStr[i] })
	return string(remainStr[0:size])
}

//getEncryptionKeysRemaining returns remaining part for secret key and iv ley
//after manipulating and adding dynamically generated nonce
func getEncryptionKeysRemaining(key1 string, key2 string, key3 string) (string, string) {
	if len(key1) > secretkeylength {
		key1 = string(key1[0:secretkeylength])
	}
	if len(key2) > secretkeylength {
		key2 = string(key2[0:secretkeylength])
	}
	var key = key1 + key2
	if len(key) > secretkeylength {
		key = string(key[0:secretkeylength])
	}
	if len(key3) > ivkeylength {
		key3 = string(key3[0:ivkeylength])
	}
	return getRemaning(key, secretkeylength-len(key)), getRemaning(key3, ivkeylength-len(key3))
}

//getReturnKeyWriteKey will return parts of randomly generate nonce that will used
//to encrypt with the file and also return back as the decrypt key for file
//decryption.
func getReturnKeyWriteKey(secretKeyRemaining string, ivKeyRemaining string) (string, string) {
	decryptKey := secretKeyRemaining + ivKeyRemaining
	if len(decryptKey) < (returnkeyPart1 + returnkeyPart2) {
		return "", ""
	}
	returnKey := string(decryptKey[0:returnkeyPart1]) + string(decryptKey[len(decryptKey)-returnkeyPart2:])
	writeKey := string(decryptKey[returnkeyPart1 : len(decryptKey)-returnkeyPart2])
	return returnKey, writeKey
}

//encryptWriteKey uses AES encrytion for the writeKey using
//unique chars from secret key, the random return key sent to user and padding string
//to make length match the required key length
func encryptText(writeKeySecret string, writeKey string) []byte {
	if len(writeKeySecret) < 16 {
		writeKeySecret = string((writeKeySecret + writeKeyToken)[0:16])
	}

	block, _ := aes.NewCipher([]byte(writeKeySecret))
	buf := make([]byte, len(writeKey))
	stream := cipher.NewCTR(block, []byte(writeKeySecret))
	stream.XORKeyStream(buf, []byte(writeKey))
	return buf
}

//decryptWriteKey uses AES decryption for writeKey using
//unique chars from secret key, the random return key sent to user and padding string
func decryptText(writeKeySecret string, writeKey []byte) string {
	if len(writeKeySecret) < 16 {
		writeKeySecret = string((writeKeySecret + writeKeyToken)[0:16])
	}
	block, _ := aes.NewCipher([]byte(writeKeySecret))
	buf := make([]byte, len(writeKey))
	stream := cipher.NewCTR(block, []byte(writeKeySecret))
	stream.XORKeyStream(buf, writeKey)
	return string(buf)
}

//getSecretKey returns secret key used for AES encrytion
//by manipulating key1, key2 and randomly generated nonce string
func getSecretKey(key1 string, key2 string, nonce string) string {
	return string(key2[len(key1)/2:]) +
		string(key1[0:len(key1)/2]) +
		string(nonce[0:len(nonce)/2]) +
		string(key1[len(key1)/2:]) +
		string(nonce[len(nonce)/2:]) +
		string(key2[0:len(key2)/2])
}

//getIVKey returns IV key used for AES encrytion
//by manipulating key and randomly generated nonce string
func getIVKey(key string, nonce string) string {
	return string(nonce[len(nonce)/2:]) +
		string(key[len(key)/2:]) +
		string(nonce[0:len(nonce)/2]) +
		string(key[0:len(key)/2])
}

//getEncryptionKeysRemainingFromFile reads the encrypted token from the files
//and returns thre remaining part for secretKey and ivKey
func getEncryptionKeysRemainingFromFile(key1 string, key2 string, uniqueChars string, writeKeySecret string, decryptKey string, fileName string) (string, string, int, error) {
	writeKeySize := secretkeylength - (len(key1) + len(key2)) + ivkeylength - len(uniqueChars) - (returnkeyPart1 + returnkeyPart2)
	writeKeyBytes := make([]byte, writeKeySize)

	infile, err := os.Open(fileName)
	if err != nil {
		return "", "", 0, err
	}
	defer infile.Close()

	fi, err := infile.Stat()
	if err != nil {
		return "", "", 0, err
	}

	msgLen := fi.Size() - int64(len(writeKeyBytes))
	_, err = infile.ReadAt(writeKeyBytes, msgLen)
	if err != nil {
		return "", "", 0, err
	}

	writeKey := string(decryptKey[0:returnkeyPart1]) + decryptText(writeKeySecret, writeKeyBytes) + string(decryptKey[returnkeyPart1:])
	secretKeyRemaining := string(writeKey[0:(secretkeylength - (len(key1) + len(key2)))])
	ivKeyRemaining := string(writeKey[(secretkeylength - (len(key1) + len(key2))):])

	return secretKeyRemaining, ivKeyRemaining, writeKeySize, nil
}

//encryptFile encrypts the file based on the secret and iv
//this will also save the file name to be encrypted in the encrypted block
//and part of the random nonce
func encryptFile(secretKey string, ivKey string, writeKeySecret string, encryptedWriteKey []byte, fileName string) (string, error) {
	infile, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer infile.Close()

	encryptedFileName := filepath.Base(infile.Name())
	fileExt := filepath.Ext(encryptedFileName)
	if len(fileExt) > 0 {
		encryptedFileName = string(encryptedFileName[0 : len(encryptedFileName)-len(fileExt)])
	}

	encryptedFile := encryptedFileName + encryptedFileExtension

	outfile, err := os.Create(encryptedFile)
	if err != nil {
		return "", err
	}
	defer outfile.Close()

	//write file name to encrypted fle
	headerFileName := encryptText(writeKeySecret, filepath.Base(infile.Name()))
	headerFileNameSize := make([]byte, 1)
	headerFileNameSize[0] = byte(len(headerFileName))
	outfile.Write(headerFileNameSize)
	outfile.Write(headerFileName)

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, []byte(ivKey))
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	//append the generated write key to the encrypted file
	outfile.Write(encryptedWriteKey)

	return encryptedFile, nil
}

//decryptFile decrypts file based on the secret and iv
func decryptFile(secretKey string, ivKey string, writeKeySecret string, writeKeySize int, encryptedFile string) (string, error) {
	infile, err := os.Open(encryptedFile)
	if err != nil {
		return "", err
	}
	defer infile.Close()

	fileNameSizeHeader := make([]byte, 1)
	_, err = infile.ReadAt(fileNameSizeHeader, 0)
	if err != nil {
		return "", err
	}

	fileNameHeader := make([]byte, fileNameSizeHeader[0])
	_, err = infile.ReadAt(fileNameHeader, 1)
	if err != nil {
		return "", err
	}
	fileName := decryptText(writeKeySecret, fileNameHeader)

	fi, err := infile.Stat()
	if err != nil {
		return "", err
	}
	msgLen := fi.Size() - int64(len(fileName)) - 1 - int64(writeKeySize)

	outfile, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer outfile.Close()

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic("Failed Creating Cipher Block with Key")
	}

	var buf []byte = make([]byte, (len(fileName) + 1))

	stream := cipher.NewCTR(block, []byte(ivKey))
	for {
		n, err := infile.Read(buf)

		if len(buf) < 1024 {
			buf = make([]byte, 1024)
			continue
		}

		if n > 0 {
			if n > int(msgLen) {
				n = int(msgLen)
			}
			msgLen -= int64(n)

			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return fileName, nil
}
