// Package postgres provides tools for working with postgres
package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type PostgresConfig struct {
	Host     string `env:"POSTGRES_HOST" env-default:"localhost"`
	Port     string `env:"POSTGRES_PORT" env-default:"5432"`
	User     string `env:"POSTGRES_USER" env-default:"postgres"`
	Password string `env:"POSTGRES_PASSWORD" env-default:"postgres"`
	DBName   string `env:"POSTGRES_DB" env-default:"postgres"`
	SSLMode  string `env:"POSTGRES_SSLMODE" env-default:"disable"`
}

type DB struct {
	*sqlx.DB
}

func New(ctx *context.Context, config PostgresConfig) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.SSLMode)
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	var exists bool
	err = db.Get(&exists, "SELECT EXISTS (SELECT datname FROM pg_catalog.pg_database WHERE datname = $1)", config.DBName)
	if err != nil {
		return nil, fmt.Errorf("failed to check if database exists: %v", err)
	}

	if !exists {
		createDBQuery := fmt.Sprintf("CREATE DATABASE %s;", config.DBName)
		if _, err = db.Exec(createDBQuery); err != nil {
			return nil, fmt.Errorf("failed to create database: %v", err)
		}
	}

	db, err = sqlx.Connect("postgres", fmt.Sprintf("%s dbname=%s", dsn, config.DBName))
	if err != nil {
		return nil, err
	}

	if _, err := db.Conn(*ctx); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}
