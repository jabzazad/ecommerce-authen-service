// Package utils is a core utils package
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"ecommerce-authen/internal/core/config"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/dgrijalva/jwt-go"
)

var (
	// SignKey is private key
	SignKey = &ecdsa.PrivateKey{}
	// VerifyKey is public key
	VerifyKey = &ecdsa.PublicKey{}
)

// ReadECDSAKey read private key && public key
func ReadECDSAKey(privateKey, publicKey string) error {
	privateKeyByte, err := os.ReadFile(privateKey)
	if err != nil {
		return err
	}

	publicKeyByte, err := os.ReadFile(publicKey)
	if err != nil {
		return err
	}

	SignKey, err = jwt.ParseECPrivateKeyFromPEM(privateKeyByte)
	if err != nil {
		return err
	}

	VerifyKey, err = jwt.ParseECPublicKeyFromPEM(publicKeyByte)
	if err != nil {
		return err
	}

	return nil
}

// Encrypt encrypt
func Encrypt(stringToEncrypt string) (encryptedString string) {
	hkey := hex.EncodeToString([]byte(config.CF.App.SecretKey))
	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(hkey)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

// Decrypt decrypt
func Decrypt(encryptedString string) (decryptedString string) {
	hkey := hex.EncodeToString([]byte(config.CF.App.SecretKey))
	enc, _ := hex.DecodeString(encryptedString)
	key, _ := hex.DecodeString(hkey)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}
