// Package render is a internal handlers render package
package render

import (
	"ecommerce-authen/internal/core/config"

	"github.com/gofiber/fiber/v2"
)

// JSON render json to client
func JSON(c *fiber.Ctx, response interface{}) error {
	return c.
		Status(config.RR.Internal.Success.HTTPStatusCode()).
		JSON(response)
}

// Download render file
func Download(c *fiber.Ctx, path, fileName string) error {
	return c.Download(path, fileName)
}

// Error render error to client
func Error(c *fiber.Ctx, err error) error {
	errMsg := config.RR.Internal.ConnectionError
	if locErr, ok := err.(config.Result); ok {
		errMsg = locErr
	}

	return c.
		Status(errMsg.HTTPStatusCode()).
		JSON(errMsg.WithLocale(c))
}
