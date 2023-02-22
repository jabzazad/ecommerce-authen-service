// Package routes routes package
package routes

import (
	ctx "context"
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/handlers/middlewares"
	"ecommerce-authen/internal/pkg/guest"
	"ecommerce-authen/internal/pkg/healthcheck"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2/middleware/pprof"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	swagger "github.com/gofiber/swagger"
	"github.com/sirupsen/logrus"
)

const (
	// MaximumSize100MB body limit 100 mb.
	MaximumSize100MB = 1024 * 1024 * 100
	// MaximumSize1MB body limit 1 mb.
	MaximumSize1MB = 1024 * 1024 * 1
)

// NewRouter new router
func NewRouter() {
	app := fiber.New(
		fiber.Config{
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    5 * time.Second,
			BodyLimit:      MaximumSize100MB,
			ReadBufferSize: MaximumSize1MB,
			JSONEncoder:    sonic.Marshal,
			JSONDecoder:    sonic.Unmarshal,
		},
	)
	app.Use(
		compress.New(),
		pprof.New(),
		requestid.New(),
		cors.New(),
		middlewares.WrapError(),
		middlewares.TransactionDatabase(func(c *fiber.Ctx) bool {
			return c.Method() == fiber.MethodGet
		}),
	)

	api := app.Group("/api")
	v1 := api.Group("/v1")
	v1.Use(middlewares.AcceptLanguage())
	v1.Use(middlewares.Logger())
	if config.CF.Swagger.Enable {
		v1.Get("/swagger/*", swagger.HandlerDefault)
	}

	// General Endpoint
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString(fmt.Sprintf("ecommerce api environment %s", config.CF.App.Env))
	})

	app.Get("/metrics", monitor.New())
	healthzEndpoint := healthcheck.NewEndpoint()
	healthz := v1.Group("healthz")
	healthz.Get("/", healthzEndpoint.HealthCheck)

	guestEndpoint := guest.NewEndpoint()
	guest := v1.Group("g")
	guest.Post("/register", guestEndpoint.Register)
	guest.Post("/login", guestEndpoint.Login)
	guest.Post("/token", guestEndpoint.RenewToken)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		_, cancel := ctx.WithTimeout(ctx.Background(), 5*time.Second)
		defer cancel()
		logrus.Info("Gracefully shutting down...")
		_ = app.Shutdown()
	}()

	logrus.Infof("Start server on port: %d ...", config.CF.App.Port)
	err := app.Listen(fmt.Sprintf(":%d", config.CF.App.Port))
	if err != nil {
		logrus.Panic(err)
	}
}
