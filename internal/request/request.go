package request

import "time"

// GetOne get one
type GetOne struct {
	ID uint `json:"-" path:"id" form:"id" query:"id"`
}

// GetOneWithKey get one with key
type GetOneWithKey struct {
	ID  uint   `json:"-" path:"id" form:"id" query:"id"`
	Key string `json:"key" form:"key" query:"key" validate:"required"`
}

// GetKey get key
type GetKey struct {
	Key string `json:"key" form:"key" query:"key" validate:"required"`
}

// GetOneString get one string
type GetOneString struct {
	ID string `json:"-" path:"id" form:"id" query:"id"`
}

// GetOneAndPermission get one and permission
type GetOneAndPermission struct {
	ID           uint `json:"-" path:"id" form:"id" query:"id"`
	PermissionID uint `query:"permission_id" json:"permission_id" form:"permission_id" validate:"required"`
}

// GetOneStringAndPermission get one and permission
type GetOneStringAndPermission struct {
	ID           string `json:"-" path:"id" form:"id" query:"id"`
	PermissionID uint   `query:"permission_id" json:"permission_id" form:"permission_id" validate:"required"`
}

// GetPermission get permission
type GetPermission struct {
	PermissionID uint `json:"permission_id" query:"permission_id" form:"permission_id" validate:"required"`
}

// GetQuery get query
type GetQuery struct {
	PermissionID uint       `json:"permission_id" query:"permission_id" form:"permission_id" validate:"required"`
	StartDate    *time.Time `json:"start_date" form:"start_date" query:"start_date" `
	EndDate      *time.Time `json:"end_date" form:"end_date" query:"end_date" `
	ShopID       uint       `json:"shop_id" form:"shop_id" query:"shop_id" `
	CompanyID    uint       `json:"company_id" form:"company_id" query:"company_id" `
}
