package utils

import "regexp"

var (
	regexCitizenID   = regexp.MustCompile(`^(\d{13})?$`)
	regexTaxID       = regexp.MustCompile(`^(\d{13}|\d{10})$`)
	regexPhoneNumber = regexp.MustCompile(`0[6|8|9]{1}\d{8}$`)
	regexEmail       = regexp.MustCompile(`^[\w-]+(\.[\w-]+)*@([a-z0-9-]+(\.[a-z0-9-]+)*?\.[a-z]{2,6}|(\d{1,3}\.){3}\d{1,3})(:\d{4})?$`)
)

// IsValidCitizenID check citizen id is valid
func IsValidCitizenID(citizenID string) bool {
	return isValidCitizenID(citizenID)
}

// IsValidTaxID check tax id is valid
func IsValidTaxID(taxID string) bool {
	return regexTaxID.MatchString(taxID)
}

// IsValidPassword check password is valid
func IsValidPassword(password string) bool {
	return len(password) >= 6
}

// IsValidPhoneNumber check phone number is valid
func IsValidPhoneNumber(phoneNumber string) bool {
	return regexPhoneNumber.MatchString(phoneNumber)
}

// IsValidEmail check email is valid
func IsValidEmail(email string) bool {
	return regexEmail.MatchString(email)
}
