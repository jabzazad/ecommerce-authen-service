// Package sql is a core sql package
package sql

import (
	"ecommerce-authen/internal/core/config"
	"fmt"

	"gorm.io/driver/postgres"

	"gorm.io/gorm"
)

var (
	// Database global variable database `postgresql`
	Database = &gorm.DB{}
)

// InitConnectionDatabase open initialize a new db connection.
func InitConnectionDatabase(config config.DatabaseConfig) (err error) {
	dns := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		config.Host,
		config.Port,
		config.Username,
		config.Password,
		config.DatabaseName,
	)

	Database, err = gorm.Open(postgres.Open(dns))
	if err != nil {
		return err
	}

	sqlDB, err := Database.DB()
	if err != nil {
		return err
	}

	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetMaxOpenConns(config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)

	return nil
}

// Debug set debug database
func Debug() {
	Database = Database.Debug()
}
