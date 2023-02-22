# ecommerce-authen

## Getting started
1. Download swag by using:
```sh
$ go get -u github.com/swaggo/swag/cmd/swag
```
2. Run `swag init` in the project's root folder which contains the `main.go` file. This will parse your comments and generate the required files (`docs` folder and `docs/docs.go`).
```sh
$ swag init
```

3. Run `go run main.go`

mockgen -package=repositories -source={absolutepath} -destination=mock_config_repo.go
