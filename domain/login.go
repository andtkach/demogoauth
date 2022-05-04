package domain

import (
	"database/sql"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Login struct {
	Username   string         `db:"username"`
	Password   string         `db:"password"`
	CustomerId sql.NullString `db:"customer_id"`
	Role       string         `db:"role"`
}

func (l Login) ClaimsForAccessToken() AccessTokenClaims {
	if l.CustomerId.Valid {
		return l.claimsForUser()
	} else {
		return l.claimsForAdmin()
	}
}

func (l Login) claimsForUser() AccessTokenClaims {
	return AccessTokenClaims{
		CustomerId: l.CustomerId.String,
		Username:   l.Username,
		Role:       l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}

func (l Login) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Username: l.Username,
		Role:     l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
