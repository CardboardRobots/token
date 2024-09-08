package token

import (
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

const (
	bearerPrefix      = "Bearer "
	bearerPrefixLower = "bearer "
)

func GetClaims(authorization string, key string, claims jwt.Claims) error {
	bearer := getBearer(authorization)

	return ParseClaims(bearer, key, claims)
}

func getBearer(authorization string) string {
	return strings.TrimPrefix(strings.TrimPrefix(
		authorization,
		bearerPrefix),
		bearerPrefixLower)
}

func ParseClaims(token string, key string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	return err
}

func CreateToken(key string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(key))
}
