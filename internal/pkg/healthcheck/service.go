package healthcheck

import (
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/core/context"
)

// Service service interface
type Service interface {
	HealthCheck(c *context.Context) error
}

type service struct {
	config *config.Configs
	result *config.ReturnResult
}

// NewService new service
func NewService() Service {
	return &service{
		config: config.CF,
		result: config.RR,
	}
}

// CheckUser check user
func (s *service) HealthCheck(c *context.Context) error {
	// sqlDB, err := sql.Database.DB()
	// if err != nil {
	// 	logrus.Errorf("get db error: %s", err)
	// 	return err
	// }

	// err = sqlDB.Ping()
	// if err != nil {
	// 	logrus.Errorf("call db error: %s", err)
	// 	return err
	// }

	return nil
}
