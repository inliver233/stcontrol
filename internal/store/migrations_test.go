package store

import (
	"strings"
	"testing"
)

func TestMigrationVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		want    int64
		wantErr bool
	}{
		{name: "0001_initial.sql", want: 1},
		{name: "42_add_index.sql", want: 42},
		{name: "missing.sql", wantErr: true},
		{name: "zero_bad.sql", wantErr: true},
		{name: "x_bad.sql", wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := migrationVersion(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("migrationVersion(%q) succeeded, want error", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("migrationVersion(%q): %v", tt.name, err)
			}
			if got != tt.want {
				t.Fatalf("migrationVersion(%q)=%d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestEmbeddedMigrationsAreOrderedAndImmutable(t *testing.T) {
	t.Parallel()

	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migrations) < 2 {
		t.Fatalf("loaded %d migrations, want at least 2", len(migrations))
	}
	for i, migration := range migrations {
		if migration.Checksum == "" || len(migration.Checksum) != 64 {
			t.Fatalf("migration %s has invalid checksum %q", migration.Name, migration.Checksum)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			t.Fatalf("migration %s is empty", migration.Name)
		}
		if i > 0 && migrations[i-1].Version >= migration.Version {
			t.Fatalf("migrations are not strictly ordered: %d then %d", migrations[i-1].Version, migration.Version)
		}
	}
}
