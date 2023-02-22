package guest

import (
	"ecommerce-authen/internal/core/bcrypt"
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/core/facebook"
	"ecommerce-authen/internal/core/firebaseauth"
	"ecommerce-authen/internal/core/utils"
	"ecommerce-authen/internal/repositories"
	"ecommerce-authen/internal/request"
	"strings"
	"sync"

	"ecommerce-authen/internal/models"
	"ecommerce-authen/internal/pkg/client"
	"ecommerce-authen/internal/pkg/token"

	"github.com/jinzhu/copier"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Service service interface
type Service interface {
	Register(c *context.Context, request *request.RegisterRequest) (*models.RefreshToken, error)
	Login(c *context.Context, request *request.LoginRequest) (*models.RefreshToken, error)
}

type service struct {
	config          *config.Configs
	result          *config.ReturnResult
	userRepository  repositories.UserRepository
	tokenService    token.Service
	firebaseService firebaseauth.Client
	clientService   client.Service
	facebookService facebook.FacebookService
	mutex           sync.Mutex
}

// NewService new service
func NewService() Service {
	return &service{
		config:          config.CF,
		result:          config.RR,
		userRepository:  repositories.UserNewRepository(),
		tokenService:    token.NewService(),
		firebaseService: firebaseauth.New(),
		facebookService: facebook.New(),
		clientService:   client.NewService(),
	}
}

// Register register
func (s *service) Register(c *context.Context, request *request.RegisterRequest) (*models.RefreshToken, error) {
	if request.Password != request.ConfirmPassword {
		return nil, s.result.PasswordNotMatch
	}

	if !utils.IsValidEmail(request.Email) {
		return nil, s.result.InvalidEmail
	}

	if request.PhoneNumber != "" {
		if !utils.IsValidPhoneNumber(request.PhoneNumber) {
			return nil, s.result.InvalidPhoneNumber
		}
	}
	if !utils.IsValidPassword(request.Password) {
		return nil, s.result.InvalidPassword
	}

	request.Email = strings.ToLower(request.Email)
	if request.PhoneNumber != "" {
		if !utils.IsValidPhoneNumber(request.PhoneNumber) {
			return nil, s.result.InvalidPhoneNumber
		}
	}

	db := c.GetDatabase()
	exists, err := s.userRepository.FindEmail(db, request.Email)
	if err != nil && err.Error() != gorm.ErrRecordNotFound.Error() {
		logrus.Errorf("find user error: %s", err)
		return nil, err
	}

	if exists != nil {
		return nil, s.result.EmailAlreadyExists
	}

	exists, err = s.userRepository.FindPhoneNumber(db, request.PhoneNumber)
	if err != nil && err.Error() != gorm.ErrRecordNotFound.Error() {
		logrus.Errorf("find user error: %	s", err)
		return nil, err
	}

	if exists != nil {
		return nil, s.result.PhoneNumberAlreadyExists
	}

	passwordHash, err := bcrypt.GeneratePassword(request.Password)
	if err != nil {
		return nil, err
	}

	user := &models.User{}
	_ = copier.Copy(user, request)
	user.Password = passwordHash
	err = s.userRepository.Create(db, user)
	if err != nil {
		logrus.Errorf("create user error: %s", err)
		return nil, err
	}

	profile := &models.Profile{
		ID:        user.ID,
		ImageURL:  request.ImageURL,
		FirstName: request.FirstName,
		LastName:  request.LastName,
	}

	err = s.CreateUserProfile(c, profile)
	if err != nil {
		return nil, err
	}

	token, err := s.tokenService.Create(c, user)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Login login service
func (s *service) Login(c *context.Context, request *request.LoginRequest) (*models.RefreshToken, error) {
	if request.Email != "" {
		if !utils.IsValidEmail(request.Email) {
			return nil, s.result.InvalidEmail
		}

	} else if request.TokenID == "" {
		return nil, s.result.Internal.BadRequest
	}

	user, err := s.selectWayFindUser(c, request)
	if err != nil {
		return nil, err
	}

	token, err := s.tokenService.Create(c, user)
	if err != nil {
		return nil, err
	}

	return token, nil
}
