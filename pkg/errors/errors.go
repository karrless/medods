package errors

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrInvalidGUID         = errors.New("invalid guid")
	ErrUnauthorized        = errors.New("no user with this token")
	ErrCreateRefreshToken  = errors.New("can't create refresh token")
	ErrWrongUserAgent      = errors.New("wrong User-Agent")
	ErrInvalidAccessToken  = errors.New("invalid access token")
	ErrDifferentIP         = errors.New("different IP")
	ErrNotUnique           = errors.New("not unique refresh token or jti")
)
