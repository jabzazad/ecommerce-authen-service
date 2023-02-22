package repositories

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Repository common repository
type Repository struct {
}

// NewRepository new repository
func NewRepository() Repository {
	return Repository{}
}

// DefaultContext default context
func (r *Repository) DefaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second*10)
}

// FindOneObjectByID find one
func (r *Repository) FindOneObjectByID(db *gorm.DB, id uint64, i interface{}) error {
	return r.FindOneObjectByField(db, "id", id, i)
}

// FindOneObjectByIDInt find one
func (r *Repository) FindOneObjectByIDInt(db *gorm.DB, id int, i interface{}) error {
	return r.FindOneObjectByField(db, "id", id, i)

}

// FindAll find all
func (r *Repository) FindAll(db *gorm.DB, i interface{}) error {
	return db.Find(i).Error
}

// FindOneObjectByIDUInt find one
func (r *Repository) FindOneObjectByIDUInt(db *gorm.DB, id uint, i interface{}) error {
	return r.FindOneObjectByField(db, "id", id, i)
}

// FindOneObjectByIDUInt64 find one
func (r *Repository) FindOneObjectByIDUInt64(db *gorm.DB, id uint64, i interface{}) error {
	return r.FindOneObjectByField(db, "id", id, i)
}

// FindOneObjectByIDString find one
func (r *Repository) FindOneObjectByIDString(db *gorm.DB, field string, value string, i interface{}) error {
	return r.FindOneObjectByField(db, field, value, i)
}

// FindOneObjectByField find one
func (r *Repository) FindOneObjectByField(db *gorm.DB, field string, value interface{}, i interface{}) error {
	return db.Where(fmt.Sprintf("%s = ?", field), value).First(i).Error
}

// Create create
func (r *Repository) Create(db *gorm.DB, i interface{}) error {
	return db.Omit(clause.Associations).Create(i).Error
}

// CreateInBatch create with batch size
func (r *Repository) CreateInBatch(db *gorm.DB, i interface{}, batchSize int) error {
	return db.Omit(clause.Associations).CreateInBatches(i, batchSize).Error
}

// CreateWithAssociation create with association
func (r *Repository) CreateWithAssociation(db *gorm.DB, i interface{}) error {
	return db.Session(&gorm.Session{FullSaveAssociations: true}).Save(i).Error
}

// Update update
func (r *Repository) Update(db *gorm.DB, i interface{}) error {
	return db.Omit(clause.Associations).Save(i).Error
}

// UpdateInBatch update with batch size
func (r *Repository) UpdateInBatch(db *gorm.DB, i interface{}, batchSize int) error {
	return db.Omit(clause.Associations).CreateInBatches(i, batchSize).Error
}

// Delete update stamp deleted_at
func (r *Repository) Delete(db *gorm.DB, i interface{}) error {
	return db.Omit(clause.Associations).Delete(i).Error
}

// HardDelete permanently delete
func (r *Repository) HardDelete(db *gorm.DB, i interface{}) error {
	return db.Unscoped().Delete(i).Error
}

// FindOneByIDFullAssociations find one by id full associations
func (r *Repository) FindOneByIDFullAssociations(db *gorm.DB, id uint64, i interface{}) error {
	return r.FindOneObjectByID(db.Preload(clause.Associations), id, i)
}

// FindAllByIDs get all by ids
func (r *Repository) FindAllByIDs(db *gorm.DB, ids []int64, i interface{}) error {
	return db.Where("id in (?)", ids).Find(i).Error
}

// FindAllByUintIDs get all by uint ids
func (r *Repository) FindAllByUintIDs(db *gorm.DB, ids []uint, i interface{}) error {
	return db.Where("id in (?)", ids).Find(i).Error
}

// FindAllByStrings get all by strings
func (r *Repository) FindAllByStrings(db *gorm.DB, field string, values []string, i interface{}) error {
	return db.Where(fmt.Sprintf("%s in (?)", field), values).Find(i).Error
}

// FindAllByField get all by field
func (r *Repository) FindAllByField(db *gorm.DB, field string, value interface{}, i interface{}) error {
	return db.Where(fmt.Sprintf("%s = ?", field), value).Find(i).Error
}

// Upsert upsert
func (r *Repository) Upsert(db *gorm.DB, uniqueKey string, columns []string, i interface{}) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: uniqueKey}},
		DoUpdates: clause.AssignmentColumns(columns),
		UpdateAll: len(columns) == 0,
	}).
		Omit(clause.Associations).
		Create(i).Error
}

// BulkUpsert bulk upsert
func (r *Repository) BulkUpsert(db *gorm.DB, uniqueKey string, columns []string, i interface{}, batchSize int) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: uniqueKey}},
		DoUpdates: clause.AssignmentColumns(columns),
		UpdateAll: len(columns) == 0,
	}).
		Omit(clause.Associations).
		CreateInBatches(i, batchSize).Error
}

// PageForm page info interface
type PageForm interface {
	GetPage() int
	GetSize() int
	GetQuery() string
}

const (
	// DefaultPage default page in page query
	DefaultPage int = 1
	// DefaultSize default size in page query
	DefaultSize int = 20
)
