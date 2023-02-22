// Package main main package
package main

import (
	"ecommerce-authen/docs"
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/core/firebaseauth"
	"ecommerce-authen/internal/core/redis"
	"ecommerce-authen/internal/core/sql"
	"ecommerce-authen/internal/handlers/routes"
	"flag"
	"fmt"

	stackdriver "github.com/TV4/logrus-stackdriver-formatter"
	"github.com/sirupsen/logrus"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	configs := flag.String("config", "configs", "set configs path, default as: 'configs'")
	environment := flag.String("environment", "local", "set environment")
	flag.Parse()

	// Init configuration
	err := config.InitConfig(*configs, *environment)
	if err != nil {
		panic(err)
	}
	//=======================================================

	// programatically set swagger info
	docs.SwaggerInfo.Title = config.CF.Swagger.Title
	docs.SwaggerInfo.Description = config.CF.Swagger.Description
	docs.SwaggerInfo.Version = config.CF.Swagger.Version
	docs.SwaggerInfo.Host = fmt.Sprintf("%s%s", config.CF.Swagger.Host, config.CF.Swagger.BaseURL)
	//=======================================================

	// set logrus
	logrus.SetReportCaller(true)
	if config.CF.App.Release {
		logrus.SetFormatter(stackdriver.NewFormatter(
			stackdriver.WithService("api"),
			stackdriver.WithVersion("v1.0.0")))
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
	logrus.Infof("Initial 'Configuration'. %+v", config.CF)
	//=======================================================

	// Init return result
	err = config.InitReturnResult("configs")
	if err != nil {
		panic(err)
	}
	//=======================================================

	// Init connection postgresql
	err = sql.InitConnectionDatabase(config.CF.PostgreSQL)
	if err != nil {
		panic(err)
	}

	if !config.CF.App.Release {
		sql.Debug()
	}
	//======================================================

	// Redis initial
	redisConfig := redis.Configuration{
		Host:     config.CF.Redis.Host,
		Port:     config.CF.Redis.Port,
		Password: config.CF.Redis.Password,
	}

	if err := redis.Init(redisConfig); err != nil {
		panic(err)
	}
	//=======================================================

	// Init firebase auth client
	if err := firebaseauth.NewClient(config.CF.Firebase.CredentialsFile); err != nil {
		panic(err)
	}

	// New router
	routes.NewRouter()
	//=======================================================
}
