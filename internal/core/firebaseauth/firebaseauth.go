package firebaseauth

import (
	"context"
	"ecommerce-authen/internal/core/config"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

var (
	ctx    = context.Background()
	client = &auth.Client{}
)

// Client firebase authentication (google, facebook)
type Client interface {
	VerifyIDToken(idToken string) (*auth.Token, error)
	GetUserByUID(uid string) (*auth.UserRecord, error)
	GetUserByEmail(email string) (*auth.UserRecord, error)
}

type firebaseAuthentication struct {
	client *auth.Client
	result *config.ReturnResult
}

// NewClient new client
func NewClient(CredentialsFile string) error {
	var err error
	var app *firebase.App
	opt := option.WithCredentialsFile(CredentialsFile)
	app, err = firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return err
	}

	client, err = app.Auth(ctx)
	if err != nil {
		return err
	}

	return nil
}

// New new firebase
func New() Client {
	return &firebaseAuthentication{
		client: client,
		result: config.RR,
	}
}

// VerifyIDToken verify idToken (idToken firebase)
func (fba *firebaseAuthentication) VerifyIDToken(idToken string) (*auth.Token, error) {
	token, err := fba.client.VerifyIDToken(ctx, idToken)
	if err != nil {
		logrus.Errorf("google verify token error:%s", err)
		return nil, fba.result.InvalidGoogleToken
	}

	return token, nil
}

// GetUserByUID get user by uid firebase
func (fba *firebaseAuthentication) GetUserByUID(uid string) (*auth.UserRecord, error) {
	user, err := fba.client.GetUser(ctx, uid)
	if err != nil {
		logrus.Errorf("[GetUserByUID] get user error:%s", err)
		return nil, err
	}

	return user, nil
}

// GetUserByEmail get user by email
func (fba *firebaseAuthentication) GetUserByEmail(email string) (*auth.UserRecord, error) {
	user, err := fba.client.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return user, nil
}
