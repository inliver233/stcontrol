// Package store 封装总控的 PostgreSQL 数据访问。
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// Store 数据访问层。
type Store struct {
	DB *sql.DB
}

// Open 连接数据库并执行迁移。
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	// 重试连接（数据库可能尚未就绪）
	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = db.PingContext(ctx); pingErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if pingErr != nil {
		return nil, fmt.Errorf("ping database: %w", pingErr)
	}

	s := &Store{DB: db}
	if err := s.migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close 关闭连接。
func (s *Store) Close() error { return s.DB.Close() }

// migrate 执行建表（幂等）。
func (s *Store) migrate(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, schemaSQL)
	return err
}
