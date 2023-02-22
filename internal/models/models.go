package models

import (
	"time"

	"gorm.io/gorm"
)

// Model common model
type Model struct {
	ID        uint           `json:"id,omitempty" gorm:"primary_key" copier:"-"`
	CreatedAt time.Time      `json:"created_at,omitempty" gorm:"type:time" copier:"-"`
	UpdatedAt time.Time      `json:"updated_at,omitempty" gorm:"type:time" copier:"-"`
	DeletedAt gorm.DeletedAt `json:"-" sql:"index" gorm:"type:time" copier:"-"`
}
