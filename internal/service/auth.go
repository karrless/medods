package service

import (
	"bytes"
	"context"
	"encoding/json"
	"medods/internal/models"
	"medods/pkg/errors"
	"medods/pkg/jwt"
	"medods/pkg/utils"
	"net/http"
	"time"
)

type AuthRepo interface {
	GetUser(guid *string) (*models.User, error)
	WriteRefreshToken(guid, refreshToken, jti, ip, userAgent string) error
	UpdateTokens(guid, jti, refreshToken, newJTI, ip, userAgent string) error
	IsRefreshTokenValid(guid, refreshToken, jti, ip, userAgent string) (string, error)
	IsValidAccessToken(jti string) error
	DeleteToken(jti string) error
}

type AuthService struct {
	ctx       *context.Context
	secretKey string
	webhook   string
	repo      AuthRepo
}

func NewAuthService(ctx *context.Context, secretKey, webhook string, repo AuthRepo) *AuthService {
	return &AuthService{ctx: ctx, secretKey: secretKey, webhook: webhook, repo: repo}
}

func (as *AuthService) getTokensPair(guid string) (string, string, string, error) {
	jti := utils.GenerateGUID()
	accessToken := jwt.NewAccessToken(guid, jti, as.secretKey)
	refreshToken, err := jwt.NewRefreshToken()
	if err != nil {
		return "", "", "", errors.ErrCreateRefreshToken
	}
	return accessToken, refreshToken, jti, nil
}

func (as *AuthService) GetAccessToken(guid, ip, userAgent string) (string, string, error) {
	if !utils.IsGUID(guid) {
		return "", "", errors.ErrInvalidGUID
	}

	user, err := as.repo.GetUser(&guid)
	if err != nil {
		return "", "", err
	}
	accessToken, refreshToken, jti, err := as.getTokensPair(user.GUID)
	if err != nil {
		return "", "", err
	}
	err = as.repo.WriteRefreshToken(guid, refreshToken, jti, ip, userAgent)
	if err != nil {
		return "", "", err
	}
	encryptedRefreshToken := utils.EncodeBase64(refreshToken)
	return accessToken, encryptedRefreshToken, nil
}

func (as *AuthService) RefreshToken(accessToken, refreshToken, ip, userAgent string) (string, string, error) {
	ok, guid, jti, err := jwt.ValidateAndGetClaims(accessToken, as.secretKey)
	if err != nil || !ok {
		return "", "", errors.ErrInvalidAccessToken
	}
	decodeRefreshToken, err := utils.DecodeBase64(refreshToken)
	if err != nil {
		return "", "", errors.ErrInvalidRefreshToken
	}
	user, err := as.repo.GetUser(&guid)
	if err != nil {
		return "", "", err
	}
	oldIP, err := as.repo.IsRefreshTokenValid(guid, decodeRefreshToken, jti, ip, userAgent)
	if oldIP == "" {
		return "", "", errors.ErrInvalidRefreshToken
	}
	if err != nil {
		switch err {
		case errors.ErrDifferentIP:
			as.sendIPWebhook(guid, oldIP, ip)
		default:
			return "", "", err
		}
	}
	newAccessToken, newRefreshToken, newJTI, err := as.getTokensPair(user.GUID)
	if err != nil {
		return "", "", err
	}
	err = as.repo.UpdateTokens(guid, jti, newRefreshToken, newJTI, ip, userAgent)
	if err != nil {
		return "", "", err
	}
	encryptedRefreshToken := utils.EncodeBase64(newRefreshToken)
	return newAccessToken, encryptedRefreshToken, nil
}

func (as *AuthService) Me(accessToken string) (string, error) {
	ok, guid, jti, err := jwt.ValidateAndGetClaims(accessToken, as.secretKey)
	if err != nil || !ok {
		return "", errors.ErrInvalidAccessToken
	}
	err = as.repo.IsValidAccessToken(jti)
	return guid, err
}

func (as *AuthService) Logout(accessToken string) error {
	ok, _, jti, err := jwt.ValidateAndGetClaims(accessToken, as.secretKey)
	if err != nil || !ok {
		return errors.ErrInvalidAccessToken
	}
	return as.repo.DeleteToken(jti)
}

func (as *AuthService) sendIPWebhook(guid, oldIP, ip string) error {

	payload := map[string]interface{}{
		"guid":      guid,
		"old_ip":    oldIP,
		"new_ip":    ip,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(as.webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
