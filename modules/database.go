package modules

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func SetupDatabase() *sql.DB {
	// Open or create the database file
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create the table if it doesn't exist
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func RegisterUser(db *sql.DB, username, password string) error {
	// Check if the username already exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("username %s already exists", username)
	}

	// Insert new user into the database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
	return err
}

func LoginUser(db *sql.DB, username, password string) error {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("username %s does not exist", username)
		}
		return err
	}
	if storedPassword != password {
		return fmt.Errorf("invalid password for user %s", username)
	}
	return nil
}
