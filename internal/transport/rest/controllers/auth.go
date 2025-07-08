package controllers

import (
	"context"
	"net/http"
	"strings"

	"medods/pkg/errors"

	"github.com/gin-gonic/gin"
)

type AuthService interface {
	GetAccessToken(guid, ip, userAgent string) (string, string, error)
	RefreshToken(accessToken, refreshToken, ip, userAgent string) (string, string, error)
	Me(accessToken string) (string, error)
	Logout(accessToken string) error
}

type AuthController struct {
	ctx     *context.Context
	service AuthService
}

func NewAuthController(ctx *context.Context, service AuthService) *AuthController {
	return &AuthController{
		ctx:     ctx,
		service: service,
	}
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type GetAccessTokenRequest struct {
	GUID string `json:"guid"`
}

type GetAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// @Summary	Get access token
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		GetAccessTokenRequest	true	"Get access token request"
// @Success	200		{object}	GetAccessTokenResponse
// @Failure	400		{object}	ErrorResponse
// @Failure	404		{object}	ErrorResponse
// @Router		/auth/token [post]
func (ac *AuthController) GetAccessToken(c *gin.Context) {
	var req GetAccessTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userAgent := c.GetHeader("User-Agent")
	ip := getClientIP(c)
	accessToken, refreshToken, err := ac.service.GetAccessToken(req.GUID, ip, userAgent)
	if err != nil {
		var status int
		switch err {
		case errors.ErrInvalidGUID:
			status = http.StatusBadRequest
		case errors.ErrUserNotFound:
			status = http.StatusNotFound
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	response := GetAccessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	c.JSON(http.StatusOK, response)
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// @Summary	Refresh access token
// @Tags		auth
// @Accept		json
// @Produce	json
// @Param		request	body		RefreshRequest	true	"Refresh access token request"
// @Success	200		{object}	RefreshResponse
// @Failure	400		{object}	ErrorResponse
// @Failure	401		{object}	ErrorResponse
// @Failure	500		{object}	ErrorResponse
// @Router		/auth/refresh [post]
// @Security	BearerAuth
func (ac *AuthController) Refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, "Unauthorized")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	userAgent := c.GetHeader("User-Agent")
	ip := getClientIP(c)
	accessToken, refreshToken, err := ac.service.RefreshToken(token, req.RefreshToken, ip, userAgent)
	if err != nil {
		var status int
		switch err {
		case errors.ErrInvalidRefreshToken:
			status = http.StatusBadRequest
		case errors.ErrUserNotFound:
		case errors.ErrWrongUserAgent:
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	response := RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	c.JSON(http.StatusOK, response)
}

type MeResponse struct {
	GUID string `json:"guid"`
}

// @Summary	Get my GUID
// @Tags		auth
// @Success	200	{object}	MeResponse
// @Failure	400	{object}	ErrorResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
// @Router		/auth/me [get]
// @Security	BearerAuth
func (ac *AuthController) Me(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, "Unauthorized")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	GUID, err := ac.service.Me(token)
	if err != nil {
		var status int
		switch err {
		case errors.ErrInvalidAccessToken:
			status = http.StatusUnauthorized
		case errors.ErrInvalidAccessToken:
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	response := MeResponse{
		GUID: GUID,
	}
	c.JSON(http.StatusOK, response)
}

type LogoutResponse struct {
	Message string `json:"message"`
}

// @Summary	Logout
// @Tags		auth
// @Produce	json
// @Success	200	{object}	LogoutResponse
// @Failure	401	{object}	ErrorResponse
// @Failure	500	{object}	ErrorResponse
// @Router		/auth/logout [post]
// @Security	BearerAuth
func (ac *AuthController) Logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, "Unauthorized")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	err := ac.service.Logout(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	response := LogoutResponse{Message: "Logout successful. Please, clean Authorization header"}
	c.JSON(http.StatusOK, response)
}

func getClientIP(c *gin.Context) string {
	forwardedIP := c.GetHeader("X-Forwarded-For")
	if forwardedIP != "" {
		return strings.Split(forwardedIP, ",")[0]
	}
	return c.ClientIP()
}
