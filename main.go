package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func main() {

	// store flags
	operation := flag.String("operation", "", "Enter a valid service name")
	serviceName := flag.String("service", "", "Add a service name")
	userName := flag.String("username", "", "Enter username")
	password := flag.String("password", "", "Enter password")

	flag.Parse()

	// operations - add, delete, fetch
	if strings.EqualFold(*operation, "add") {
		addCredential(*serviceName, *userName, *password)
	} else if strings.EqualFold(*operation, "fetch") {
		fetchCredentials(true)
	} else if strings.EqualFold(*operation, "delete") {
		deleteFromFile(*serviceName)
	}

}

func addCredential(serviceName, userName, password string) {

	var existingCredentials = fetchCredentials(false)

	for _, cred := range existingCredentials {
		if strings.EqualFold(serviceName, cred.Service) {
			fmt.Printf("Service already exists.")
			return
		}
	}

	encryptedPassword, nonce, err := encrypt(password, encryptionKey)

	newCredential := Credential{
		Service:  serviceName,
		Username: userName,
		Password: encryptedPassword,
		Nonce:    nonce,
	}

	existingCredentials = append(existingCredentials, newCredential)

	data, err := json.MarshalIndent(existingCredentials, "", "  ")
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}

	if err := os.WriteFile(credentialFile, data, 0644); err != nil {
		fmt.Println("Error writing to file:", err)
	} else {
		fmt.Println("Added service successfully.")
	}
	return
}

func fetchCredentials(displayFlag bool) []Credential {
	var existingCredentials []Credential

	file, _ := ioutil.ReadFile(credentialFile)
	json.Unmarshal(file, &existingCredentials)

	if displayFlag {
		for _, cred := range existingCredentials {
			var decreyptedPassword, _ = decrypt(cred.Password, cred.Nonce, encryptionKey)
			fmt.Printf("{Service : %s , Username : %s , Password : %s} \n", cred.Service, cred.Username, decreyptedPassword)
		}
	}

	return existingCredentials
}

func deleteFromFile(serviceName string) {

	var existingCredentials = fetchCredentials(false)
	var updatedCredentials = deleteCredentials(existingCredentials, serviceName)

	updatedData, err := json.MarshalIndent(updatedCredentials, "", "  ")
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}

	if err := os.WriteFile(credentialFile, updatedData, 0644); err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

func deleteCredentials(existingCredentials []Credential, service string) []Credential {

	var modifiedCredential []Credential
	for _, cred := range existingCredentials {
		if cred.Service != service {
			modifiedCredential = append(modifiedCredential, cred)
		}
	}
	return modifiedCredential

}

type Credential struct {
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Nonce    string `json:"nonce"`
}

const credentialFile = "data.json"

var encryptionKey = []byte("3a7f4b8c9d2e6f103b7c1a5e8d4f2c0b")

func encrypt(plaintext string, key []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), nil
}

func decrypt(ciphertext, nonce string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decodedCiphertext, _ := base64.StdEncoding.DecodeString(ciphertext)
	decodedNonce, _ := base64.StdEncoding.DecodeString(nonce)

	plaintext, err := aesGCM.Open(nil, decodedNonce, decodedCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
