package client

import (
	"ecommerce-authen/internal/core/config"
	"ecommerce-authen/internal/models"

	"github.com/imroc/req"
	"github.com/sirupsen/logrus"
)

// Service service interface
type Service interface {
	GetRequest(url string, header interface{}, param interface{}, v interface{}) error
	PostRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error
	PutRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error
	PatchRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error
	DeleteRequest(url string, header interface{}, param interface{}, v interface{}) error
}

type service struct {
	config *config.Configs
	result *config.ReturnResult
}

// NewService new service
func NewService() Service {
	return &service{
		config: config.CF,
		result: config.RR,
	}
}

// GetRequest get request
func (s *service) GetRequest(url string, header interface{}, param interface{}, v interface{}) error {
	req.Debug = !s.config.App.Release
	response, err := req.Get(url, header, param)
	if err != nil {
		logrus.Errorf("[getRequest] request get error: %s", err)
		return err
	}

	if response.Response().StatusCode >= 200 && response.Response().StatusCode < 300 {
		err = response.ToJSON(v)
		if err != nil {
			logrus.Errorf("[getRequest] convert json response from body to struct error: %s", err)
			return err
		}
		return nil
	} else if response.Response().StatusCode == 401 {
		return s.result.Internal.Unauthorized
	}

	res := models.Message{}

	_ = response.ToJSON(&res)
	if res.Code == 1048 {
		return s.result.LoginAgain
	}

	return s.result.Internal.BadRequest
}

// PostRequest post request
func (s *service) PostRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error {
	req.Debug = !s.config.App.Release
	response, err := req.Post(url, header, param, req.BodyJSON(body))
	if err != nil {
		logrus.Errorf("request post error")
		return err
	}

	if response.Response().StatusCode >= 200 && response.Response().StatusCode < 300 {
		if v != nil {
			err = response.ToJSON(v)
			if err != nil {
				logrus.Errorf("convert json error")
				return err
			}
		}

		return nil
	} else if response.Response().StatusCode == 401 {
		return s.result.Internal.Unauthorized
	}

	return s.result.Internal.BadRequest
}

// PutRequest put request
func (s *service) PutRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error {
	req.Debug = !s.config.App.Release
	response, err := req.Put(url, header, param, req.BodyJSON(body))
	if err != nil {
		logrus.Errorf("request put error")
		return err
	}

	if response.Response().StatusCode >= 200 && response.Response().StatusCode < 300 {
		if v != nil {
			err = response.ToJSON(v)
			if err != nil {
				logrus.Errorf("convert json error")
				return err
			}
		}

		return nil
	} else if response.Response().StatusCode == 401 {
		return s.result.Internal.Unauthorized
	}

	return s.result.Internal.BadRequest
}

// PatchRequest patch request
func (s *service) PatchRequest(url string, header interface{}, param interface{}, body interface{}, v interface{}) error {
	req.Debug = !s.config.App.Release
	response, err := req.Patch(url, header, param, req.BodyJSON(body))
	if err != nil {
		logrus.Errorf("request put error")
		return err
	}

	if response.Response().StatusCode >= 200 && response.Response().StatusCode < 300 {
		if v != nil {
			err = response.ToJSON(v)
			if err != nil {
				logrus.Errorf("convert json error")
				return err
			}
		}

		return nil
	}

	return s.result.Internal.BadRequest
}

// DeleteRequest delete request
func (s *service) DeleteRequest(url string, header interface{}, param interface{}, v interface{}) error {
	req.Debug = !s.config.App.Release
	response, err := req.Delete(url, header, param)
	if err != nil {
		logrus.Errorf("request delete error")
		return err
	}

	if response.Response().StatusCode >= 200 && response.Response().StatusCode < 300 {
		if v != nil {
			err = response.ToJSON(v)
			if err != nil {
				logrus.Errorf("convert json error")
				return err
			}
		}

		return nil
	} else if response.Response().StatusCode == 401 {
		return s.result.Internal.Unauthorized
	}

	return s.result.Internal.BadRequest
}
