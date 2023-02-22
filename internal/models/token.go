package models

import (
	"time"
)

// RefreshToken model
type RefreshToken struct {
	UserID       uint       `json:"-"`
	Role         UserRole   `json:"role,omitempty"`
	JWTToken     string     `json:"token,omitempty"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiredAt    *time.Time `json:"-"`
}
