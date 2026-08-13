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

func TestMigrationAndLeadershipLocksAreDomainSeparated(t *testing.T) {
	t.Parallel()

	if migrationLockID == controllerAdvisoryLockID {
		t.Fatal("migration lock must not block a passive Controller behind active leadership")
	}
}

func TestReplicaRetentionMigrationRepairsBothReplicaProjections(t *testing.T) {
	t.Parallel()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var sqlText string
	for _, migration := range migrations {
		if migration.Name == "0038_replica_retention_cleanup.sql" {
			sqlText = migration.SQL
			break
		}
	}
	if sqlText == "" {
		t.Fatal("replica retention migration is not embedded")
	}
	for _, required := range []string{
		"UPDATE user_replicas replica SET state='stale'",
		"UPDATE replica_copies copy SET state='stale'",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_replica_one_ready_archive",
		"CREATE TABLE IF NOT EXISTS replica_cleanup_tasks",
		"'automatic_repair'",
	} {
		if !strings.Contains(sqlText, required) {
			t.Fatalf("replica retention migration missing %q", required)
		}
	}
}
