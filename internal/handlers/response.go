// Package handlers is a handlers package
package handlers

import (
	"reflect"

	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/handlers/render"
	"ecommerce-authen/internal/models"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// ResponseObject handle response object
func ResponseObject(c *fiber.Ctx, fn interface{}, request interface{}) error {
	ctx := context.WithContext(c)
	err := ctx.BindValue(request, true)
	if err != nil {
		logrus.Errorf("bind value error: %s", err)
		return render.Error(c, err)
	}

	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(request),
	})
	errObj := out[1].Interface()
	if errObj != nil {
		logrus.Errorf("call service error: %s", errObj)
		return render.Error(c, errObj.(error))
	}

	return render.JSON(c, out[0].Interface())
}

// ResponseOnlyObject handle response object
func ResponseOnlyObject(c *fiber.Ctx, fn interface{}, request interface{}) error {
	ctx := context.WithContext(c)
	err := ctx.BindValue(request, true)
	if err != nil {
		logrus.Errorf("bind value error: %s", err)
		return render.Error(c, err)
	}

	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(request),
	})

	return render.JSON(c, out[0].Interface())
}

// ResponseObjectWithoutRequest handle response object without request
func ResponseObjectWithoutRequest(c *fiber.Ctx, fn interface{}) error {
	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(context.WithContext(c)),
	})
	errObj := out[1].Interface()
	if errObj != nil {
		logrus.Errorf("call service error: %s", errObj)
		return render.Error(c, errObj.(error))
	}

	return render.JSON(c, out[0].Interface())
}

// ResponseSuccess handle response success
func ResponseSuccess(c *fiber.Ctx, fn interface{}, request interface{}) error {
	ctx := context.WithContext(c)
	err := ctx.BindValue(request, true)
	if err != nil {
		logrus.Errorf("bind value error: %s", err)
		return render.Error(c, err)
	}

	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(request),
	})
	errObj := out[0].Interface()
	if errObj != nil {
		if errObj.(error) == config.RR.StillProcess {
			return render.JSON(c, errObj.(error))
		}

		logrus.Errorf("call service error: %s", errObj)
		return render.Error(c, errObj.(error))
	}
	return render.JSON(c, models.NewSuccessMessage())
}

// ResponseSuccessWithoutRequest handle response success without request
func ResponseSuccessWithoutRequest(c *fiber.Ctx, fn interface{}) error {
	ctx := context.WithContext(c)
	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
	})
	errObj := out[0].Interface()
	if errObj != nil {
		logrus.Errorf("call service error: %s", errObj)
		return render.Error(c, errObj.(error))
	}
	return render.JSON(c, models.NewSuccessMessage())
}

// ResponseFile handle response file
func ResponseFile(c *fiber.Ctx, fn interface{}, request interface{}) error {
	ctx := context.WithContext(c)
	err := ctx.BindValue(request, true)
	if err != nil {
		logrus.Errorf("bind value error: %s", err)
		return render.Error(c, err)
	}

	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(request),
	})
	errObj := out[2].Interface()
	if errObj != nil {
		logrus.Errorf("call service error: %s", errObj)
		return render.Error(c, errObj.(error))
	}

	return render.Download(c, out[0].String(), out[1].String())
}

// ResponseCustomSuccess handle response success
func ResponseCustomSuccess(c *fiber.Ctx, fn interface{}, request interface{}) error {
	ctx := context.WithContext(c)
	err := ctx.BindValue(request, true)
	if err != nil {
		logrus.Errorf("bind value error: %s", err)
		return render.Error(c, err)
	}

	out := reflect.ValueOf(fn).Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(request),
	})

	return render.JSON(c, out[0].Interface())
}
