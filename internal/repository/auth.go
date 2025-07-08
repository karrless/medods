package repository

import (
	"context"
	"database/sql"
	"medods/internal/models"
	"medods/pkg/db/postgres"
	"medods/pkg/errors"
	"medods/pkg/utils"

	"github.com/lib/pq"
)

// type AuthRepo interface {
// 	+++GetUser(guid *string) (models.User, error)
// 	+++WriteRefreshToken(guid, refreshToken, jti, ip, userAgent string) error
// 	UpdateTokens(guid, refreshToken, jti, ip, userAgent string) error
// 	+++IsRefreshTokenValid(guid, refreshToken, jti, ip, userAgent string) (string, error)
// 	+++DeleteToken(jti string) error
// }

type AuthRepo struct {
	ctx *context.Context
	db  *postgres.DB
}

func NewAuthRepo(ctx *context.Context, db *postgres.DB) *AuthRepo {
	return &AuthRepo{ctx: ctx, db: db}
}

func (ar *AuthRepo) GetUser(guid *string) (*models.User, error) {
	var user models.User
	query := `SELECT guid from public.users where guid=$1;`
	err := ar.db.QueryRow(query, guid).Scan(&user.GUID)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, errors.ErrUserNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}

func (ar *AuthRepo) DeleteToken(jti string) error {
	query := `DELETE FROM tokens WHERE jti = $1`
	_, err := ar.db.Exec(query, jti)
	if err != nil {
		return err
	}
	return nil
}

func (ar *AuthRepo) IsRefreshTokenValid(guid, refreshToken, jti, ip, userAgent string) (string, error) {
	var tokenRow models.TokenRow
	query := `SELECT jti, refresh_token, ip, user_agent, user_guid from public.tokens where jti=$1;`
	err := ar.db.QueryRow(query, jti).Scan(&tokenRow.JTI, &tokenRow.RefreshToken, &tokenRow.IP, &tokenRow.UserAgent, &tokenRow.GUID)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return "", errors.ErrInvalidAccessToken
		default:
			return "", err
		}
	}
	ok, err := utils.CheckStirngHash(refreshToken, tokenRow.RefreshToken)
	if !ok {
		println(err)
		return "", errors.ErrInvalidRefreshToken
	}
	if tokenRow.UserAgent != userAgent {
		err = ar.DeleteToken(jti)
		if err != nil {
			return "", err
		}
		return "", errors.ErrWrongUserAgent
	}
	if tokenRow.IP != ip {
		err = errors.ErrDifferentIP
	}
	return tokenRow.IP, err
}

func (ar *AuthRepo) WriteRefreshToken(guid, refreshToken, jti, ip, userAgent string) error {
	hashedRefresh, err := utils.HashString(refreshToken)
	if err != nil {
		return err
	}
	query := `INSERT INTO public.tokens (jti, refresh_token, ip, user_agent, user_guid) VALUES ($1, $2, $3, $4, $5)`
	_, err = ar.db.Exec(query, jti, hashedRefresh, ip, userAgent, guid)
	if err != nil {
		pgErr, ok := err.(*pq.Error)
		if ok {
			if pgErr.Code == "23505" {
				return errors.ErrNotUnique
			}
			if pgErr.Code == "23503" {
				return errors.ErrUserNotFound
			}
		}
	}
	return err
}

func (ar *AuthRepo) UpdateTokens(guid, jti, refreshToken, newJTI, ip, userAgent string) error {
	err := ar.DeleteToken(jti)
	if err != nil {
		return err
	}
	err = ar.WriteRefreshToken(guid, refreshToken, newJTI, ip, userAgent)
	return err
}

func (ar *AuthRepo) IsValidAccessToken(jti string) error {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM public.tokens WHERE jti = $1)`
	err := ar.db.Get(&exists, query, jti)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrInvalidAccessToken
	}
	return nil
}
