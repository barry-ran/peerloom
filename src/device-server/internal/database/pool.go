package database

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	config.MaxConns = 10
	config.MinConns = 0
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot initialize database pool")
	}
	return pool, nil
}

func Ready(pool *pgxpool.Pool, version int64) func(context.Context) error {
	return func(ctx context.Context) error {
		var got int64
		err := pool.QueryRow(ctx, "SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&got)
		if err != nil || got != version {
			return errors.New("database schema is not ready")
		}
		return nil
	}
}
