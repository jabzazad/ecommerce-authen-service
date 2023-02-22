// Package otp is a core otp package
package otp

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const period = (60 * time.Minute)

// Interface otp interface
type Interface interface {
	GenerateCode() (string, string, error)
	ValidateCode(code, secret string) bool
}

// New otp
func New() Interface {
	return &OTP{}
}

// OTP object
type OTP struct{}

// GenerateCode generate code
func (o OTP) GenerateCode() (string, string, error) {
	second := uint(period.Seconds())
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "jabzazad",
		AccountName: "jabzazad",
		Period:      second,
	})
	if err != nil {
		return "", "", err
	}

	opts := totp.ValidateOpts{
		Period:    second,
		Digits:    4,
		Algorithm: otp.AlgorithmSHA1,
	}
	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now().UTC(), opts)

	return code, key.Secret(), err
}

// ValidateCode validate code
func (o OTP) ValidateCode(code, secret string) bool {
	second := uint(period.Seconds())
	opts := totp.ValidateOpts{
		Period:    second,
		Digits:    4,
		Algorithm: otp.AlgorithmSHA1,
	}
	success, err := totp.ValidateCustom(code, secret, time.Now().UTC(), opts)
	if err != nil {

		panic(err)
	}
	// fmt.Println("err : ",err)

	return success
}
