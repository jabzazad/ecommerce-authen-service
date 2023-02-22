package middlewares

import (
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/core/sql"

	"gorm.io/gorm"

	"github.com/gofiber/fiber/v2"
)

type (
	// Skipper defines a function to skip middleware. Returning true skips processing
	Skipper func(*fiber.Ctx) bool
)

// TransactionDatabase to do transaction database
func TransactionDatabase(skipper Skipper) fiber.Handler {
	return func(c *fiber.Ctx) (err error) {
		database := &gorm.DB{}
		skip := skipper(c)
		defer func() {
			if r := recover(); r != nil {
				if !skip {
					_ = database.Rollback()
				}

				stackTrace(c, r)
			}
		}()

		if !skip {
			database = sql.Database.Begin()
			c.Locals(context.PostgreDatabaseKey, database)
			err = c.Next()
			if err != nil {
				_ = database.Rollback()
			}

			if database.Commit().Error != nil {
				_ = database.Rollback()
			}
		} else {
			_ = c.Next()
		}

		return
	}
}
