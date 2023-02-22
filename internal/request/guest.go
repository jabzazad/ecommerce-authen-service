package request

import (
	"ecommerce-authen/internal/models"
)

// RegisterRequest register request
type RegisterRequest struct {
	FirstName       string `json:"first_name" example:"jabzazad"`
	LastName        string `json:"last_name" example:"Developer"`
	Email           string `json:"email" example:"test@hotmail.com" validate:"required"`
	Password        string `json:"password" example:"P@ssw0rd"`
	ConfirmPassword string `json:"confirm_password" example:"P@ssw0rd"`
	ImageURL        string `json:"image_url" example:"https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"`
	PhoneNumber     string `json:"phone_number"`
	Address         string `json:"address"`
	AcceptPolicy    bool   `json:"accept_policy"`
	ReferenceCode   string `json:"reference_code"`
}

// LoginRequest login request
type LoginRequest struct {
	Email     string           `json:"email" example:"test@hotmail.com"`
	Password  string           `json:"password" example:"P@ssw0rd"`
	TokenID   string           `json:"token_id"`
	LoginType models.LoginType `json:"login_type"`
}

// EmailRequest request
type EmailRequest struct {
	Email string `json:"email" example:"test@hotmail.com"`
}

// ResetPassword request
type ResetPassword struct {
	Otp             string `json:"otp"`
	Email           string `json:"email" `
	Password        string `json:"password" example:"P@ssw0rd"`
	ConfirmPassword string `json:"confirm_password" example:"P@ssw0rd"`
}
