// Package crypto for ckureit utility test cases which performs AES-256 encryption of a given file
package crypto

import (
	"fmt"
	"os"
	"testing"
)

//TestValidateRequired tests for required input
func TestValidateRequired(t *testing.T) {
	invalidInput := " "
	_, err1 := validateRequired(invalidInput)
	if err1 == nil {
		t.Fatalf("FAIL TestValidateRequired test for invalidInput")
	}

	validInput := " testing  "
	validText, err2 := validateRequired(validInput)
	if err2 != nil {
		t.Fatalf("FAIL TestValidateRequired failed for validInput")
	}
	if fmt.Sprintf("%q", validText) != fmt.Sprintf("%q", "testing") {
		t.Fatalf("FAIL TestValidateRequired validInput test \n\texpected: [%s],\n\tactual:   [%s]", validText, "testing")
	}
	t.Logf("PASS TestValidateRequired test")
}

//TestValidateSecretKeyLength tests for required secret input
func TestValidateSecretKeyLength(t *testing.T) {
	invalidInput := " "
	_, err := validateSecretKeyLength(invalidInput)
	if err == nil {
		t.Fatalf("FAIL TestValidateSecretKeyLength test for invalidInput")
	}

	invalidInput1 := "Test"
	_, err = validateSecretKeyLength(invalidInput1)
	if err == nil {
		t.Fatalf("FAIL TestValidateSecretKeyLength test for invalidInput1")
	}

	invalidInput2 := "Test1Test1Test1Test1Test1"
	_, err = validateSecretKeyLength(invalidInput2)
	if err == nil {
		t.Fatalf("FAIL TestValidateSecretKeyLength test for invalidInput2")
	}

	validInput := " Test1Test1Test1  "
	validText, err3 := validateSecretKeyLength(validInput)
	if err3 != nil {
		t.Fatalf("FAIL TestValidateSecretKeyLength failed for validInput")
	}
	if fmt.Sprintf("%q", validText) != fmt.Sprintf("%q", "Test1Test1Test1") {
		t.Fatalf("FAIL TestValidateSecretKeyLength failed for validInput \n\texpected: [%s],\n\tactual:   [%s]", validText, "Test1Test1Test1")
	}
	t.Logf("PASS TestValidateSecretKeyLength test")
}

//TestRemoveDuplicates test to removing duplicate chars from string
func TestRemoveDuplicates(t *testing.T) {
	expected := "Test1"
	input1 := "Test1"
	if fmt.Sprintf("%q", removeDuplicates(input1)) != fmt.Sprintf("%q", expected) {
		t.Fatalf("FAIL TestRemoveDuplicates failed for input1 \n\texpected: [%s],\n\tactual:   [%s]", input1, expected)
	}
	input2 := "Test1Test1"
	if fmt.Sprintf("%q", removeDuplicates(input2)) != fmt.Sprintf("%q", expected) {
		t.Fatalf("FAIL TestRemoveDuplicates failed for input2 \n\texpected: [%s],\n\tactual:   [%s]", input2, expected)
	}
	t.Logf("PASS TestRemoveDuplicates test")
}

//TestPrepareEncryptionKeys test preparation of encryption keys
func TestPrepareEncryptionKeys(t *testing.T) {
	var key1 = ""
	var key2 = ""
	var key3 = ""

	key1, key2, key3 = prepareEncryptionKeys("TestSecretKey")
	if key1 != "TestSe" || key2 != "cretKey" || key3 != "TestScrKy" {
		t.Fatalf("FAIL TestPrepareEncryptionKeys failed for inputs ")
	}
	key1, key2, key3 = prepareEncryptionKeys("TestSecretKey1235690TestSecretKey1235690TestSecretKey1235690")
	if key1 != "TestSecretKey123" || key2 != "Key1235690TestSe" || key3 != "TestScrKy1" {
		t.Fatalf("FAIL TestPrepareEncryptionKeys failed for inputs ")
	}

	key1, key2, key3 = prepareEncryptionKeys("TestSecretKey1235690TestSecretKey1235690TestSecretKey1235690TestSecretKey1235690TestSecretKey1235690")
	if key1 != "TestSecretKey123" || key2 != "Key1235690TestSe" || key3 != "TestScrKy1" {
		t.Fatalf("FAIL TestPrepareEncryptionKeys failed for inputs ")
	}
	t.Logf("PASS TestPrepareEncryptionKeys test")
}

//TestGetRemaning test function to validate string appended with dynamically generated
//nonce for making string of given length
func TestGetRemaning(t *testing.T) {
	if len(getRemaning("III", 5)) != 5 {
		t.Fatalf("FAIL TestGetRemaning failed for size 5 ")
	}
	if len(getRemaning("TESTTEST", 8)) != 8 {
		t.Fatalf("FAIL TestGetRemaning failed for size 6 ")
	}

	t.Logf("PASS TestGetRemaning test")
}

//TestGetEncryptionKeysRemaining test function to validate string appended with dynamically generated
//nonce for making string of given length for secret and iv
func TestGetEncryptionKeysRemaining(t *testing.T) {
	var secretRemaining = ""
	var ivRemaining = ""
	secretRemaining, ivRemaining = getEncryptionKeysRemaining("", "", "")
	if len(secretRemaining) != secretkeylength || len(ivRemaining) != ivkeylength {
		t.Fatalf("FAIL TestGetEncryptionKeysRemaining failed for empty string ")
	}

	secretRemaining, ivRemaining = getEncryptionKeysRemaining("t", "t", "t")
	if len(secretRemaining) != (secretkeylength-2) || len(ivRemaining) != (ivkeylength-1) {
		t.Fatalf("FAIL TestGetEncryptionKeysRemaining failed for single char string ")
	}
	secretRemaining, ivRemaining = getEncryptionKeysRemaining("test1test112test1test112test1test112test1test112test1test112test1test112test1test112test1test112", "test1test112test1test112test1test112test1test112test1test112test1test112test1test112test1test112", "test1test112test1test112test1test112test1test112test1test112test1test112test1test112test1test112")
	if len(secretRemaining) != 0 || len(ivRemaining) != 0 {
		t.Fatalf("FAIL TestGetEncryptionKeysRemaining failed for large string ")
	}
	t.Logf("PASS TestGetEncryptionKeysRemaining test")
}

//TestGetReturnKeyWriteKey validates the return on the return key provided for decryption
//and the write key that is encrypted with the encrypted file
func TestGetReturnKeyWriteKey(t *testing.T) {
	var returnKey = ""
	var writeKey = ""
	returnKey, writeKey = getReturnKeyWriteKey("Test1", "1Test")
	if returnKey != "Teest" || writeKey != "st11T" {
		t.Fatalf("FAIL TestGetReturnKeyWriteKey failed for Test1 1Test")
	}
	returnKey, writeKey = getReturnKeyWriteKey("1", "1Test1Test1Test1Test1Test")
	if returnKey != "11est" || writeKey != "Test1Test1Test1Test1T" {
		t.Fatalf("FAIL TestGetReturnKeyWriteKey failed for Test1 1Test")
	}
	returnKey, writeKey = getReturnKeyWriteKey("T1", "1T")
	if returnKey != "" || writeKey != "" {
		t.Fatalf("FAIL TestGetReturnKeyWriteKey failed for T1 T1")
	}
	t.Logf("PASS TestGetReturnKeyWriteKey test")
}

//TestEncryptText validate encryption of the writeKey
func TestEncryptText(t *testing.T) {
	encrypted := encryptText("TEST", "TEST")
	if len(encrypted) != 4 {
		t.Fatalf("FAIL TestEncryptText failed")
	}
	t.Logf("PASS TestEncryptText test ")
}

//TestDecryptText validate decrytion of writeKey
func TestDecryptText(t *testing.T) {
	encrypted := encryptText("TEST", "TEST")
	if len(encrypted) != 4 {
		t.Fatalf("FAIL TestDecryptText encryption failed")
	}
	decrypted := decryptText("TEST", encrypted)
	if decrypted != "TEST" {
		t.Fatalf("FAIL TestDecryptText decryption failed")
	}
	t.Logf("PASS TestDecryptText test ")
}

//TestGetSecretKey validates generating of secret key
func TestGetSecretKey(t *testing.T) {
	secretKey := getSecretKey("TEST", "ONE", "NEW")
	if secretKey != "ETENSTEWO" {
		t.Fatalf("FAIL TestGetSecretKey failed")
	}
	t.Logf("PASS TestGetSecretKey test ")
}

//TestGetSecretKey validates generating of secret key
func TestGetIVKey(t *testing.T) {
	ivKey := getIVKey("TEST", "ONE")
	if ivKey != "NESTOTE" {
		t.Fatalf("FAIL TestGetIVKey failed")
	}
	t.Logf("PASS TestGetIVKey test ")
}

//TestEncrypt test encryption of file
func TestEncrypt(t *testing.T) {
	_, _, err := Encrypt(" ", " ")
	if err == nil {
		t.Fatalf("FAIL TestEncrypt failed for invalid values")
	}
	_, _, err = Encrypt(" ", "test")
	if err == nil {
		t.Fatalf("FAIL TestEncrypt failed for invalid secret key")
	}
	_, _, err = Encrypt("test1test112", " ")
	if err == nil {
		t.Fatalf("FAIL TestEncrypt failed for invalid filename ")
	}
	_, _, err = Encrypt("CKUREITTESTPASSWORDKEYCKUREITTESTPASSWORDKEY", "CKUREITTESTPASSWORDKEY ")
	if err == nil {
		t.Fatalf("FAIL TestEncrypt failed for invalid secret key ")
	}

	_, _, err = Encrypt("CKUREITTESTPASSWORDKEY", "FAKE.FILE")
	if err == nil {
		t.Fatalf("FAIL TestEncrypt failed for invalid file")
	}
}

//TestDecrypt test decryption of file
func TestDecrypt(t *testing.T) {
	_, err := Decrypt(" ", " ", " ")
	if err == nil {
		t.Fatalf("FAIL TestDecrypt failed for invalid values")
	}
	_, err = Decrypt("TEST", " ", " ")
	if err == nil {
		t.Fatalf("FAIL TestDecrypt failed for invalid secret key")
	}
	_, err = Decrypt("TESTCKUREITPASSKEY1", " ", " ")
	if err == nil {
		t.Fatalf("FAIL TestDecrypt failed for invalid file name")
	}
	_, err = Decrypt("TESTCKUREITPASSKEY1", "TEST1.TXT", " ")
	if err == nil {
		t.Fatalf("FAIL TestDecrypt failed for invalid decrypt token")
	}

	filename, decryptKey, err := Encrypt("CKUREITTESTPASSWORDKEY", "../go.mod")
	if err != nil || len(decryptKey) == 0 {
		t.Fatalf("FAIL TestDecrypt failed for valid encryption ")
	}

	fileDecrypted, err := Decrypt("CKUREITTESTPASSWORDKEY", filename, decryptKey)
	if err != nil {
		t.Fatalf("FAIL TestDecrypt failed for valid input")
	}

	os.Remove(filename)
	os.Remove(fileDecrypted)

	t.Logf("PASS TestDecrypt test ")
}
