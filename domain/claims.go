package domain

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Minute
const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type RefreshTokenClaims struct {
	TokenType  string `json:"token_type"`
	CustomerId string `json:"cid"`
	Username   string `json:"un"`
	Role       string `json:"role"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	CustomerId string `json:"customer_id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}

func (c AccessTokenClaims) IsValidCustomerId(customerId string) bool {
	return c.CustomerId == customerId
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.CustomerId != urlParams["customer_id"] {
		return false
	}

	return true
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:  "refresh_token",
		CustomerId: c.CustomerId,
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		CustomerId: c.CustomerId,
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
