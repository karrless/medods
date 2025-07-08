// Package config
package config

import (
	"log"
	"medods/internal/transport/rest"
	"medods/pkg/db/postgres"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config
type Config struct {
	postgres.PostgresConfig
	rest.ServerConfig
	Debug     bool   `env:"DEBUG" env-default:"false"`
	SecretKey string `env:"SHA512KEY" env-default:"secrets"`
	Webhook   string `env:"WEBHOOK" env-default:"http://localhost:9090/webhook"`
}

// New
func New() *Config {
	cfg := Config{}

	err := cleanenv.ReadConfig("./.env", &cfg)

	if err != nil {
		log.Fatalf("error reading config: %v`", err)
	}

	return &cfg
}
