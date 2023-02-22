package models

import (
	"time"
)

// LoginType login channel
type LoginType uint

const (
	// LoginTypeUnknown login channel
	LoginTypeUnknown LoginType = iota
	// LoginTypeNormal login normal
	LoginTypeNormal
	// LoginTypeGoogle login channel
	LoginTypeGoogle
	// LoginTypeFacebook login channel
	LoginTypeFacebook
)

// UserRole user role
type UserRole uint

const (
	// UnknownRole unknown role
	UnknownRole UserRole = iota
	// RoleCustomer user role customer
	RoleCustomer
	// RoleShopEmployee role shop employee
	RoleSeller UserRole = 5
	// RoleUser user role user
	RoleAdmin UserRole = 10
)

// User user model
type User struct {
	Model
	Email        string     `json:"email"`
	Password     string     `json:"-"`
	PhoneNumber  string     `json:"phone_number"`
	Role         UserRole   `json:"role,omitempty" copier:"-"`
	IsActive     bool       `json:"is_active"`
	GoogleID     string     `json:"google_id"`
	FacebookID   string     `json:"facebook_id"`
	AcceptPolicy bool       `json:"accept_policy"`
	LastOnlineAt *time.Time `json:"last_online_at,omitempty"`
}

// TableName override table name
func (User) TableName() string {
	return "users"
}
