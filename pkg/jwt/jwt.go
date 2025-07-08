package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/rand"
)

// NewAccessToken returns a new access token
func NewAccessToken(guid, jti, secret string) string {
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims = jwt.MapClaims{
		"sub": guid,
		"jti": jti,
	}
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func ValidateAndGetClaims(accessToken, secret string) (valid bool, guid, jti string, err error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return false, "", "", err
	}

	if !token.Valid {
		return false, "", "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, "", "", fmt.Errorf("invalid claims format")
	}

	guid, ok1 := claims["sub"].(string)
	jti, ok2 := claims["jti"].(string)

	if !ok1 || !ok2 {
		return false, "", "", fmt.Errorf("missing required claims")
	}

	return true, guid, jti, nil
}

func NewRefreshToken() (string, error) {
	b := make([]byte, 32)

	s := rand.NewSource(uint64(time.Now().Unix()))
	r := rand.New(s)

	if _, err := r.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
