package models

// Type type model
type Type struct {
	Code  string `json:"code,omitempty"`
	Name  string `json:"name"`
	Value int    `json:"value"`
}
