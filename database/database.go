package database

import (
	"database/sql"
	"log"
	"os"
)

const dataFile = "var/sqlite/data.db"

type Db interface {
	Setup() error
	Conn() *sql.DB
	Destroy() error
}

type db struct {
	conn *sql.DB
}

func New() Db {
	conn, err := sql.Open("sqlite3", dataFile)

	if err != nil {
		log.Fatal(err)
	}

	db := &db{
		conn,
	}

	err = db.Setup()

	if err != nil {
		log.Fatal(err)
	}

	return db
}

func (db *db) Setup() error {
	content, err := os.ReadFile("database/scripts/init.sql")

	if err != nil {
		return err
	}

	_, err = db.conn.Exec(string(content))

	return err
}

func (db *db) Conn() *sql.DB {
	return db.conn
}

func (db *db) Destroy() error {
	return os.Remove(dataFile)
}
