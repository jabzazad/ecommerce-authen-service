// Package bcrypt implements password hashing using the bcrypt algorithm.
package bcrypt

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// ComparePassword compare password
func ComparePassword(passwordHash, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return false
	}

	return true
}

// GeneratePassword generate password
func GeneratePassword(password string) (string, error) {
	passwordHashByte, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		logrus.Errorf("[GeneratePassword] generate password error:%s", err)
		return "", err
	}

	return string(passwordHashByte), nil
}
