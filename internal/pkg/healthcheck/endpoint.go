// Package healthcheck is a healthcheck package
package healthcheck

import (
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/handlers"

	"github.com/gofiber/fiber/v2"
)

// Endpoint guest endpoint
type Endpoint interface {
	HealthCheck(c *fiber.Ctx) error
}

type endpoint struct {
	config  *config.Configs
	result  *config.ReturnResult
	service Service
}

// NewEndpoint new endpoint guest
func NewEndpoint() Endpoint {
	return &endpoint{
		config:  config.CF,
		result:  config.RR,
		service: NewService(),
	}
}

// HealthCheck
// @Tags HealthCheck
// @Summary HealthCheck
// @Description HealthCheck server
// @Accept json
// @Produce json
// @Param Accept-Language header string false "(en, th)" default(th)
// @Success 200 {object} models.Message
// @Failure 400 {object} models.Message
// @Failure 401 {object} models.Message
// @Failure 404 {object} models.Message
// @Failure 410 {object} models.Message
// @Router /healthz [get]
func (ep *endpoint) HealthCheck(c *fiber.Ctx) error {
	return handlers.ResponseSuccessWithoutRequest(c, ep.service.HealthCheck)
}
