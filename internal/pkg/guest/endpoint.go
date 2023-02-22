// Package guest package
package guest

import (
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/handlers"
	"ecommerce-authen/internal/pkg/token"
	"ecommerce-authen/internal/request"

	"github.com/gofiber/fiber/v2"
)

// Endpoint endpoint interface
type Endpoint interface {
	Register(c *fiber.Ctx) error
	Login(c *fiber.Ctx) error
	RenewToken(c *fiber.Ctx) error
}

type endpoint struct {
	config       *config.Configs
	result       *config.ReturnResult
	service      Service
	tokenService token.Service
}

// NewEndpoint new endpoint
func NewEndpoint() Endpoint {
	return &endpoint{
		config:       config.CF,
		result:       config.RR,
		service:      NewService(),
		tokenService: token.NewService(),
	}
}

// Register register
// @Tags Guest
// @Summary Register
// @Description Register
// @Accept json
// @Produce json
// @Param Accept-Language header string false "(en, th)" default(th)
// @Param request body request.RegisterRequest true "request body"
// @Success 200 {object} models.RefreshToken
// @Failure 400 {object} models.Message
// @Failure 401 {object} models.Message
// @Failure 404 {object} models.Message
// @Failure 410 {object} models.Message
// @Router /g/register [post]
func (ep *endpoint) Register(c *fiber.Ctx) error {
	return handlers.ResponseObject(c, ep.service.Register, &request.RegisterRequest{})
}

// Login login
// @Tags Guest
// @Summary Login
// @Description Login
// @Accept json
// @Produce json
// @Param Accept-Language header string false "(en, th)" default(th)
// @Param request body request.LoginRequest true "request body"
// @Success 200 {object} models.RefreshToken
// @Failure 400 {object} models.Message
// @Failure 401 {object} models.Message
// @Failure 404 {object} models.Message
// @Failure 410 {object} models.Message
// @Router /g/login [post]
func (ep *endpoint) Login(c *fiber.Ctx) error {
	return handlers.ResponseObject(c, ep.service.Login, &request.LoginRequest{})
}

// RenewToken renew token
// @Tags Guest
// @Summary RenewToken
// @Description RenewToken
// @Accept json
// @Produce json
// @Param Accept-Language header string false "(en, th)" default(th)
// @Param request body request.RefreshTokenRequest true "request body"
// @Success 200 {object} models.RefreshToken
// @Failure 400 {object} models.Message
// @Failure 401 {object} models.Message
// @Failure 404 {object} models.Message
// @Failure 410 {object} models.Message
// @Router /g/token [post]
func (ep *endpoint) RenewToken(c *fiber.Ctx) error {
	return handlers.ResponseObject(c, ep.tokenService.RenewToken, &request.RefreshTokenRequest{})
}
