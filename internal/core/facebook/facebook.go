package facebook

import (
	"ecommerce-authen/internal/core/config"

	"github.com/sirupsen/logrus"

	"github.com/huandu/facebook"
)

type FacebookService interface {
	GetFacebookUser(token string) (*facebookUser, error)
}

type facebookUser struct {
	ID         string
	Email      string
	FirstName  string
	LastName   string
	PictureURL string
}

type facebookService struct {
	result *config.ReturnResult
}

func New() FacebookService {
	return &facebookService{result: config.RR}
}

func (s *facebookService) GetFacebookUser(token string) (*facebookUser, error) {
	facebook.Version = "v10.0"
	res, err := facebook.Get("/me", facebook.Params{
		"fields":       "id,first_name,last_name,email,picture.width(960)",
		"access_token": token,
	})
	if err != nil {
		logrus.Errorf("[GetFacebookUser] facebook get me error: %s", err)
		return nil, s.result.InvalidFacebookToken
	}

	facebookUser := &facebookUser{}
	facebookUser.ID = res.Get("id").(string)
	facebookUser.FirstName = res.Get("first_name").(string)
	facebookUser.LastName = res.Get("last_name").(string)
	if res.Get("email") != nil {
		facebookUser.Email = res.Get("email").(string)
	}

	if res.Get("picture.data.url") != nil {
		facebookUser.PictureURL = res.Get("picture.data.url").(string)
	}

	return facebookUser, nil
}
