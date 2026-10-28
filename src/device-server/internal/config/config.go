// Package config loads bounded configuration without exposing secrets in errors.
package config

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddress   string
	DatabaseURL     string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	return LoadWith(os.Getenv, os.ReadFile)
}

func LoadWith(getenv func(string) string, readFile func(string) ([]byte, error)) (Config, error) {
	c := Config{ListenAddress: ":8080", ShutdownTimeout: 10 * time.Second}
	if address := getenv("LISTEN_ADDRESS"); address != "" {
		if _, _, err := net.SplitHostPort(address); err != nil {
			return Config{}, errors.New("LISTEN_ADDRESS must be a host:port")
		}
		c.ListenAddress = address
	}
	c.DatabaseURL = strings.TrimSpace(getenv("DATABASE_URL"))
	path := getenv("DATABASE_URL_FILE")
	if c.DatabaseURL != "" && path != "" {
		return Config{}, errors.New("set only one of DATABASE_URL and DATABASE_URL_FILE")
	}
	if path != "" {
		data, err := readFile(path)
		if err != nil {
			return Config{}, errors.New("cannot read DATABASE_URL_FILE")
		}
		c.DatabaseURL = strings.TrimSpace(string(data))
	}
	if c.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL or DATABASE_URL_FILE is required")
	}
	return c, nil
}
