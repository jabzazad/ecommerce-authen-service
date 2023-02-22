package token

import (
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/core/redis"
	"ecommerce-authen/internal/models"
	"ecommerce-authen/internal/repositories"
	"ecommerce-authen/internal/request"

	"github.com/sirupsen/logrus"
)

// Service service interface
type Service interface {
	Create(c *context.Context, u *models.User) (*models.RefreshToken, error)
	RenewToken(c *context.Context, f *request.RefreshTokenRequest) (*models.RefreshToken, error)
}

type service struct {
	config         *config.Configs
	result         *config.ReturnResult
	userRepository repositories.UserRepository
}

// NewService new service
func NewService() Service {
	return &service{
		config:         config.CF,
		result:         config.RR,
		userRepository: repositories.UserNewRepository(),
	}
}

// Create create token
func (s *service) Create(c *context.Context, u *models.User) (*models.RefreshToken, error) {
	a, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	conn := redis.GetConnection()
	err = conn.Set(a.JWTToken, u.ID, s.config.JWT.ExpireTime)
	if err != nil {
		logrus.Errorf("set jwt token error: %s", err)
		return nil, err
	}

	err = conn.Set(a.RefreshToken, u.ID, s.config.JWT.RefreshTokenExpireTime)
	if err != nil {
		logrus.Errorf("set refresh token error: %s", err)
		return nil, err
	}

	return a, nil
}

// RenewToken renew token
func (s *service) RenewToken(c *context.Context, f *request.RefreshTokenRequest) (*models.RefreshToken, error) {
	conn := redis.GetConnection()
	var userID uint
	err := conn.Get(f.RefreshToken, &userID)
	if err != nil {
		logrus.Errorf("get user id from refresh token error: %s", err)
		return nil, err
	}

	u := &models.User{}
	if err := s.userRepository.FindOneObjectByIDUInt(c.GetDatabase(), userID, u); err != nil {
		logrus.Errorf("find user by token userID=%d error:%s", userID, err)
		return nil, s.result.Internal.DatabaseNotFound
	}

	a, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	err = conn.Delete(f.RefreshToken)
	if err != nil {
		logrus.Errorf("delete refresh token in redis error: %s", err)
		return nil, err
	}

	err = conn.Set(a.JWTToken, u.ID, s.config.JWT.ExpireTime)
	if err != nil {
		logrus.Errorf("set jwt token error: %s", err)
		return nil, err
	}

	err = conn.Set(a.RefreshToken, u.ID, s.config.JWT.RefreshTokenExpireTime)
	if err != nil {
		logrus.Errorf("set refresh token error: %s", err)
		return nil, err
	}

	return a, nil
}
