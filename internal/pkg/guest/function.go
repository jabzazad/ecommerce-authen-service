package guest

import (
	"ecommerce-authen/internal/core/bcrypt"
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/models"
	"ecommerce-authen/internal/request"
	"fmt"
	"strings"

	"firebase.google.com/go/auth"
	"github.com/imroc/req"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func (s *service) selectWayFindUser(c *context.Context, request *request.LoginRequest) (*models.User, error) {
	switch request.LoginType {
	case models.LoginTypeGoogle:
		user, err := s.loginWithGoogle(c, request)
		if err != nil {
			return nil, s.result.Internal.DatabaseNotFound
		}

		return user, nil

	case models.LoginTypeFacebook:
		user, err := s.loginWithFacebook(c, request.TokenID)
		if err != nil {
			return nil, err
		}

		return user, nil

	}

	user, err := s.loginNormal(c, request)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *service) loginWithFacebook(c *context.Context, token string) (*models.User, error) {
	db := c.GetDatabase()
	if token == "" {
		return nil, s.result.InvalidFacebookToken
	}

	fb, err := s.facebookService.GetFacebookUser(token)
	if err != nil {
		return nil, s.result.InvalidFacebookToken
	}

	user, err := s.userRepository.FindByFacebookID(db, fb.ID)
	if err != nil && err.Error() != gorm.ErrRecordNotFound.Error() {
		logrus.Errorf(" find user by facebookID=%s error: %s", fb.ID, err)
		return nil, err
	}

	if user == nil {
		newUser := &models.User{
			FacebookID: fb.ID,
		}

		profile := &models.Profile{
			FirstName: fb.FirstName,
			LastName:  fb.LastName,
		}

		if fb.Email != "" {
			user, err = s.userRepository.FindEmail(db, fb.Email)
			if err != nil {
				if err.Error() != gorm.ErrRecordNotFound.Error() {
					logrus.Errorf("find user by email=%s error: %s", fb.Email, err)
					return nil, err
				}

				newUser.Email = fb.Email
			}

			if user != nil {
				user.FacebookID = fb.ID
				err = s.userRepository.Update(db, user)
				if err != nil {
					logrus.Errorf("update googleID on userID=%d error: %s", user.ID, err)
					return nil, err
				}

				return user, nil
			}

		}

		if fb.PictureURL != "" {
			profile.ImageURL = fb.PictureURL
		}

		err = s.userRepository.Create(db, &newUser)
		if err != nil {
			logrus.Errorf(" create user error: %s", err)
			return nil, s.result.Internal.ConnectionError
		}

		profile.ID = newUser.ID
		err = s.CreateUserProfile(c, profile)
		if err != nil {
			return nil, err
		}

		return newUser, nil
	}

	return user, nil
}

func (s *service) loginWithGoogle(c *context.Context, request *request.LoginRequest) (*models.User, error) {
	firebaseUser, err := s.getFirebaseUser(request.TokenID)
	if err != nil {
		return nil, err
	}

	googleID := firebaseUser.ProviderUserInfo[0].UID
	user, err := s.userRepository.FindByGoogleID(c.GetDatabase(), googleID)
	if err != nil && err.Error() != gorm.ErrRecordNotFound.Error() {
		logrus.Errorf("find user by googleID=%s error: %s", googleID, err)
		return nil, err
	}

	if user == nil {
		user, err = s.userRepository.FindEmail(c.GetDatabase(), firebaseUser.ProviderUserInfo[0].Email)
		if err != nil {
			if err.Error() != gorm.ErrRecordNotFound.Error() {
				logrus.Errorf("find user by email error: %s", err)
				return nil, err
			}

			newUser := &models.User{}
			profile := &models.Profile{
				ImageURL: firebaseUser.ProviderUserInfo[0].PhotoURL,
			}
			name := strings.Split(firebaseUser.ProviderUserInfo[0].DisplayName, " ")
			if len(name) > 1 {
				profile.LastName = name[len(name)-1]
			}

			profile.FirstName = name[0]
			newUser.Email = firebaseUser.ProviderUserInfo[0].Email
			newUser.GoogleID = googleID
			err = s.userRepository.Create(c.GetDatabase(), newUser)
			if err != nil {
				logrus.Errorf("create user error: %s", err)
				return nil, err
			}

			profile.ID = newUser.ID
			err = s.CreateUserProfile(c, profile)
			if err != nil {
				return nil, err
			}

			return newUser, nil
		}

		user.GoogleID = googleID
		err = s.userRepository.Update(c.GetDatabase(), user)
		if err != nil {
			logrus.Errorf("update googleID on userID=%d error: %s", user.ID, err)
			return nil, err
		}
	}

	return user, nil
}

func (s *service) loginNormal(c *context.Context, request *request.LoginRequest) (*models.User, error) {
	request.Email = strings.ToLower(request.Email)
	user, err := s.userRepository.FindEmail(c.GetDatabase(), request.Email)
	if err != nil {
		logrus.Errorf("find user by email error: %s", err)
		return nil, s.result.NotFoundEmailInSystem
	}

	if !bcrypt.ComparePassword(user.Password, request.Password) {
		return nil, s.result.InvalidPassword
	}

	return user, nil
}

func (s *service) getFirebaseUser(idToken string) (*auth.UserRecord, error) {
	if idToken == "" {
		return nil, s.result.InvalidGoogleToken
	}

	token, err := s.firebaseService.VerifyIDToken(idToken)
	if err != nil {
		return nil, s.result.InvalidGoogleToken
	}

	firebaseUser, err := s.firebaseService.GetUserByUID(token.UID)
	if err != nil {
		return nil, s.result.InvalidGoogleToken
	}

	if len(firebaseUser.ProviderUserInfo) == 0 {
		return nil, s.result.InvalidGoogleToken
	}

	return firebaseUser, nil
}

// CreateUserProfile create user profile
func (s *service) CreateUserProfile(c *context.Context, profile *models.Profile) error {
	header := req.Header{
		"accept-language": c.GetLanguage(),
	}

	response := &models.Message{}
	url := fmt.Sprintf("%s%s", s.config.User.URL, s.config.User.Path.Profile)
	err := s.clientService.PostRequest(url, header, nil, profile, response)
	if err != nil {
		return err
	}

	return nil
}
