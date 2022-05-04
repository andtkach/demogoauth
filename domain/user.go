package domain

import (
	"database/sql"
)

type User struct {
	Username   string         `db:"username"`
	CustomerId sql.NullString `db:"customer_id"`
	Role       string         `db:"role"`
}
