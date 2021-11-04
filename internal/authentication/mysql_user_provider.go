package authentication

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"log"
	"sync"
	"time"
)

type MysqlUserProvider struct {
	database      *sql.DB
	configuration *schema.MysqlAuthenticationBackendConfiguration
	lock          *sync.Mutex
}

func NewMysqlUserProvider(configuration *schema.MysqlAuthenticationBackendConfiguration) *MysqlUserProvider {
	connectionString := configuration.Connection.Username

	if configuration.Connection.Password != "" {
		connectionString += fmt.Sprintf(":%s", configuration.Connection.Password)
	}

	if connectionString != "" {
		connectionString += "@"
	}

	address := configuration.Connection.Host
	if configuration.Connection.Port > 0 {
		address += fmt.Sprintf(":%d", configuration.Connection.Port)
	}

	connectionString += fmt.Sprintf("tcp(%s)", address)
	if configuration.Connection.Database != "" {
		connectionString += fmt.Sprintf("/%s", configuration.Connection.Database)
	}

	connectionString += "?"
	connectionString += fmt.Sprintf("timeout=%ds", int32(configuration.Connection.Timeout/time.Second))

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(configuration.Password.Algorithm)
	return &MysqlUserProvider{
		configuration: configuration,
		database:      db,
		lock:          &sync.Mutex{},
	}
}

func (p *MysqlUserProvider) CheckUserPassword(username string, password string) (valid bool, err error) {
	var passwordHash string
	err = p.database.QueryRow("SELECT password FROM user where username = ?", username).Scan(&passwordHash)
	if err != nil {
		return false, err
	}
	ok, err := CheckPassword(password, passwordHash)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (p *MysqlUserProvider) GetDetails(username string) (details *UserDetails, err error) {
	details = &UserDetails{Username: username, Groups: []string{}}

	var email string
	var groupsJSON string
	err = p.database.
		QueryRow("SELECT email, `groups`, display_name FROM user WHERE username = ?", username).
		Scan(&email, &groupsJSON, &details.DisplayName)

	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(groupsJSON), &details.Groups)
	if err != nil {
		return nil, err
	}

	details.Emails = append(details.Emails, email)
	return details, nil
}

func (p *MysqlUserProvider) UpdatePassword(username string, newPassword string) (err error) {
	algorithm, err := ConfigAlgoToCryptoAlgo(p.configuration.Password.Algorithm)
	if err != nil {
		return err
	}

	hash, err := HashPassword(
		newPassword, "", algorithm, p.configuration.Password.Iterations,
		p.configuration.Password.Memory*1024, p.configuration.Password.Parallelism,
		p.configuration.Password.KeyLength, p.configuration.Password.SaltLength)

	if err != nil {
		return err
	}

	_, err = p.database.Query("UPDATE user SET password = ? WHERE username = ?", hash, username)
	return err
}

func (p *MysqlUserProvider) StartupCheck(logger *logrus.Logger) (err error) {
	err = p.database.Ping()
	if err != nil {
		logger.Error("Cant ping mysql")
	}
	return err
}
