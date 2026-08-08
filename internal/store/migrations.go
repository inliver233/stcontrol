package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Keep migration serialization in a different advisory-lock namespace from
// the long-lived Controller leadership lock. A passive Controller must be
// able to verify already-applied migrations while the active Controller owns
// leadership.
const migrationLockID int64 = 0x53544d4947524154 // "STMIGRAT"

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	Version  int64
	Name     string
	SQL      string
	Checksum string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, previous, entry.Name())
		}
		data, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(data)
		migrations = append(migrations, migration{
			Version:  version,
			Name:     entry.Name(),
			SQL:      string(data),
			Checksum: hex.EncodeToString(sum[:]),
		})
		seen[version] = entry.Name()
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

func migrationVersion(name string) (int64, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok || prefix == "" {
		return 0, fmt.Errorf("migration %q must start with a numeric version followed by underscore", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("migration %q has invalid version", name)
	}
	return version, nil
}

// migrate applies immutable embedded migrations under a PostgreSQL advisory lock.
// Each migration is committed independently so a failed migration never appears
// in schema_migrations and can safely be retried after correction.
func (s *Store) migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	// Pin a session lock for the entire sequence while retaining one transaction
	// per migration. Locking each migration only after BeginTx is insufficient:
	// a waiter can retain a pre-wait SERIALIZABLE snapshot and then fail while
	// recording a migration that the previous process just committed.
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockID)
	}()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, m := range migrations {
		if err := s.applyMigration(ctx, conn, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", m.Name, err)
	}
	defer func() { _ = tx.Rollback() }()

	var checksum string
	err = tx.QueryRowContext(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, m.Version).Scan(&checksum)
	switch {
	case err == nil:
		if checksum != m.Checksum {
			return fmt.Errorf("migration %s checksum changed after it was applied", m.Name)
		}
		return tx.Commit()
	case err != sql.ErrNoRows:
		return fmt.Errorf("check migration %s: %w", m.Name, err)
	}

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("apply migration %s: %w", m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1,$2,$3)`,
		m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("record migration %s: %w", m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.Name, err)
	}
	return nil
}
