package repositories

import (
	"gorm.io/gorm"
)

// FileRepository repo interface
type FileRepository interface {
	Create(db *gorm.DB, i interface{}) error
	FindAllByIDs(db *gorm.DB, ids []int64, i interface{}) error
	BulkUpsert(db *gorm.DB, uniqueKey string, columns []string, i interface{}, batchSize int) error
}

type filerepository struct {
	Repository
}

// FileNewRepository new sql repository
func FileNewRepository() FileRepository {
	return &filerepository{
		NewRepository(),
	}
}
