package domain

import (
	"database/sql"
	"github.com/ashishjuyal/banking-lib/errs"
	"github.com/ashishjuyal/banking-lib/logger"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type AuthRepository interface {
	VerifyUser(username string, password string) (*Login, *errs.AppError)
	UserExists(username string) (bool, *errs.AppError)
	CreateUser(username string, password string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
}

const dbTSLayout = "2006-01-02 15:04:05"

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "select refresh_token from refresh_token_store where refresh_token = ?"
	var token string
	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}
	return nil
}

func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	// generate the refresh token
	var appErr *errs.AppError
	var refreshToken string
	if refreshToken, appErr = authToken.newRefreshToken(); appErr != nil {
		return "", appErr
	}

	// store it in the store
	sqlInsert := "insert into refresh_token_store (refresh_token) values (?)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}

func (d AuthRepositoryDb) VerifyUser(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := `SELECT u.username, u.password, u.customer_id, u.role FROM users u WHERE u.username = ?`
	err := d.client.Get(&login, sqlVerify, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}

	match := checkPasswordHash(password, login.Password)
	if !match {
		return nil, errs.NewAuthenticationError("invalid credentials")
	}

	return &login, nil
}

func (d AuthRepositoryDb) UserExists(username string) (bool, *errs.AppError) {
	var user User
	sqlVerify := `SELECT username FROM users u WHERE username = ?`
	err := d.client.Get(&user, sqlVerify, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		} else {
			return false, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return true, nil
}

func (d AuthRepositoryDb) CreateUser(username, password string) (*Login, *errs.AppError) {
	role := "user"
	sqlInsert := "INSERT INTO users (username, password, role, created_on) values (?, ?, ?, ?)"
	hash, _ := hashPassword(password)
	_, err := d.client.Exec(sqlInsert, username, hash, role, time.Now().Format(dbTSLayout))
	if err != nil {
		logger.Error("Error while creating new account: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected error from database")
	}

	return &Login{Username: username, Role: role}, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client}
}
