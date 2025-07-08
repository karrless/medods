// Package migrations provides tools for working with migrations
package migrations

import (
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
)

func Up(db *sqlx.DB) (int, error) {
	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		return -1, err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver,
	)

	if err != nil {
		return -1, err
	}

	err = m.Up()
	if err != nil {
		if err == migrate.ErrNoChange {
			return -1, nil
		}
		return -1, err
	}

	version, _, err := m.Version()
	if err != nil {
		return 0, err
	}
	return int(version), nil
}
