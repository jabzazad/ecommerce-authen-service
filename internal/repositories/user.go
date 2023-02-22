package repositories

import (
	"ecommerce-authen/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepository repo interface
type UserRepository interface {
	Create(db *gorm.DB, i interface{}) error
	Update(db *gorm.DB, i interface{}) error
	FindOneObjectByIDUInt(db *gorm.DB, id uint, i interface{}) error
	FindOneByIDFullAssociations(db *gorm.DB, id uint64, i interface{}) error
	FindEmail(database *gorm.DB, email string) (*models.User, error)
	BulkUpsert(db *gorm.DB, uniqueKey string, columns []string, i interface{}, batchSize int) error
	FindByGoogleID(db *gorm.DB, tokenID string) (*models.User, error)
	FindOneByIDWithPreload(db *gorm.DB, userID uint) (*models.User, error)
	FindByFacebookID(db *gorm.DB, tokenID string) (*models.User, error)
	FindPhoneNumber(database *gorm.DB, phoneNumber string) (*models.User, error)
}

type userRepository struct {
	Repository
}

// UserNewRepository new sql repository
func UserNewRepository() UserRepository {
	return &userRepository{
		NewRepository(),
	}
}

// FindEmail find email
func (repo *userRepository) FindEmail(database *gorm.DB, email string) (*models.User, error) {
	entity := &models.User{}
	err := database.Where("email ilike ?", email).First(entity).Error
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindPhoneNumber find phone number
func (repo *userRepository) FindPhoneNumber(database *gorm.DB, phoneNumber string) (*models.User, error) {
	entity := &models.User{}
	err := database.Where("phone_number = ?", phoneNumber).First(entity).Error
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindByGoogleID find by token id
func (repo *userRepository) FindByGoogleID(db *gorm.DB, tokenID string) (*models.User, error) {
	entity := &models.User{}
	err := db.Where("google_id = ?", tokenID).First(entity).Error
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindOneByIDWithPreload find one by id with preload
func (repo *userRepository) FindOneByIDWithPreload(db *gorm.DB, userID uint) (*models.User, error) {
	entity := &models.User{}
	err := db.Where("id = ?", userID).Preload(clause.Associations).Preload("Subscruibe", func(db *gorm.DB) *gorm.DB {
		return db.Unscoped()
	}).First(entity).Error
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// FindByFacebookID find by token id
func (repo *userRepository) FindByFacebookID(db *gorm.DB, tokenID string) (*models.User, error) {
	entity := &models.User{}
	err := db.Where("facebook_id = ?", tokenID).First(entity).Error
	if err != nil {
		return nil, err
	}

	return entity, nil
}
