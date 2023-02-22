// Package token provides a token generator and validator.
package token

import (
	"crypto/sha256"
	"ecommerce-authen/internal/core/context"
	"ecommerce-authen/internal/models"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/gommon/random"
	"github.com/sirupsen/logrus"
)

func generateRefreshToken(userID string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(fmt.Sprintf("%s_%s_%s", userID, time.Now().String(), random.String(4))))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return strings.ToLower(sha)
}

func (s *service) generateAccessToken(i interface{}) (*models.RefreshToken, error) {
	var userID uint
	var role models.UserRole
	if u, ok := i.(*models.User); ok {
		userID = u.ID
		role = u.Role
	} else if t, ok := i.(*models.RefreshToken); ok {
		userID = t.UserID
		role = t.Role
	}

	now := time.Now()
	c := &context.Claims{
		Role: role,
	}

	c.Subject = fmt.Sprintf("%d", userID)
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(s.config.JWT.ExpireTime).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	t, err := token.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		logrus.Errorf("[generateAccessToken] signed string error:%s", err)
		return nil, err
	}

	refreshTokenExpireTime := now.Add(s.config.JWT.RefreshTokenExpireTime)
	accessToken := &models.RefreshToken{
		UserID:       userID,
		JWTToken:     t,
		RefreshToken: generateRefreshToken(fmt.Sprintf("%d", userID)),
		ExpiredAt:    &refreshTokenExpireTime,
		Role:         role,
	}

	return accessToken, nil
}
