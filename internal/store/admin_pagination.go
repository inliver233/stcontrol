package store

import (
	"context"
	"errors"
	"math"
	"strings"
)

var ErrInvalidAdminPage = errors.New("invalid admin page request")

type AdminOverviewCounts struct {
	Nodes            int64 `json:"nodes"`
	NodesOnline      int64 `json:"nodes_online"`
	NodesOffline     int64 `json:"nodes_offline"`
	NodesFull        int64 `json:"nodes_full"`
	NodesBusy        int64 `json:"nodes_busy"`
	NodesMaintenance int64 `json:"nodes_maintenance"`
	NodesFault       int64 `json:"nodes_fault"`
	Users            int64 `json:"users"`
	BackupRunning    int64 `json:"backup_running"`
	BackupFailed     int64 `json:"backup_failed"`
}

func (s *Store) GetAdminOverviewCounts(ctx context.Context) (AdminOverviewCounts, error) {
	var counts AdminOverviewCounts
	err := s.DB.QueryRowContext(ctx, `
		SELECT COUNT(*),
		  COUNT(*) FILTER (WHERE connectivity_state='online'),
		  COUNT(*) FILTER (WHERE connectivity_state='offline'),
		  COUNT(*) FILTER (WHERE role='compute' AND capacity_state='full'),
		  COUNT(*) FILTER (WHERE role='compute' AND capacity_state='busy'),
		  COUNT(*) FILTER (WHERE operational_state IN ('maintenance','draining')),
		  COUNT(*) FILTER (WHERE connectivity_state='offline'
		    OR operational_state IN ('failed','degraded')),
		  (SELECT COUNT(*) FROM users),
		  (SELECT COUNT(*) FROM backup_jobs WHERE status IN ('running','pending','verifying')),
		  (SELECT COUNT(*) FROM backup_jobs WHERE status='failed')
		FROM nodes`).Scan(
		&counts.Nodes, &counts.NodesOnline, &counts.NodesOffline, &counts.NodesFull,
		&counts.NodesBusy, &counts.NodesMaintenance, &counts.NodesFault, &counts.Users,
		&counts.BackupRunning, &counts.BackupFailed,
	)
	return counts, err
}

type UserPageParams struct {
	AfterID int64
	Limit   int
	Query   string
	Status  string
}

type UserPage struct {
	Users      []*User
	NextCursor int64
	HasMore    bool
}

func (s *Store) ListUsersPage(ctx context.Context, params UserPageParams) (UserPage, error) {
	params.Query = strings.TrimSpace(params.Query)
	if params.AfterID < 0 || params.Limit <= 0 || params.Limit > 100 || len(params.Query) > 128 ||
		(params.Status != "" && params.Status != "active" && params.Status != "disabled" && params.Status != "conflict") {
		return UserPage{}, ErrInvalidAdminPage
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT user_account.id,COALESCE(global_user.id,0),user_account.uuid,
		  user_account.username,user_account.display_name,user_account.auth_provider,
		  user_account.avatar_url,user_account.home_node_id,user_account.status,user_account.created_at
		FROM users user_account
		LEFT JOIN global_users global_user ON global_user.legacy_user_id=user_account.id
		WHERE user_account.id>$1
		  AND ($2='' OR user_account.username ILIKE '%'||$2||'%'
		    OR user_account.display_name ILIKE '%'||$2||'%'
		    OR user_account.uuid::text ILIKE '%'||$2||'%')
		  AND ($3='' OR user_account.status=$3)
		ORDER BY user_account.id LIMIT $4`, params.AfterID, params.Query, params.Status, params.Limit+1)
	if err != nil {
		return UserPage{}, err
	}
	defer rows.Close()
	page := UserPage{Users: make([]*User, 0, params.Limit)}
	for rows.Next() {
		user := &User{}
		if err := rows.Scan(
			&user.ID, &user.GlobalID, &user.UUID, &user.Username, &user.DisplayName,
			&user.AuthProvider, &user.AvatarURL, &user.HomeNodeID, &user.Status, &user.CreatedAt,
		); err != nil {
			return UserPage{}, err
		}
		if len(page.Users) == params.Limit {
			page.HasMore = true
			break
		}
		page.Users = append(page.Users, user)
		page.NextCursor = user.ID
	}
	if err := rows.Err(); err != nil {
		return UserPage{}, err
	}
	if !page.HasMore {
		page.NextCursor = 0
	}
	return page, nil
}

type BackupPageParams struct {
	BeforeID int64
	Limit    int
	Status   string
	UserID   int64
}

type BackupPage struct {
	Jobs       []*BackupJob
	NextCursor int64
	HasMore    bool
}

func (s *Store) ListBackupJobsPage(ctx context.Context, params BackupPageParams) (BackupPage, error) {
	validStatus := params.Status == "" || params.Status == "pending" || params.Status == "running" ||
		params.Status == "verifying" || params.Status == "done" || params.Status == "failed" ||
		params.Status == "aborted"
	if params.BeforeID < 0 || params.UserID < 0 || params.Limit <= 0 || params.Limit > 100 || !validStatus {
		return BackupPage{}, ErrInvalidAdminPage
	}
	beforeID := params.BeforeID
	if beforeID == 0 {
		beforeID = math.MaxInt64
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id,user_id,src_node_id,dst_node_id,trigger,status,data_version,bytes,
		  file_count,error,started_at,finished_at,created_at
		FROM backup_jobs
		WHERE id<$1 AND ($2='' OR status=$2) AND ($3=0 OR user_id=$3)
		ORDER BY id DESC LIMIT $4`, beforeID, params.Status, params.UserID, params.Limit+1)
	if err != nil {
		return BackupPage{}, err
	}
	defer rows.Close()
	page := BackupPage{Jobs: make([]*BackupJob, 0, params.Limit)}
	for rows.Next() {
		job := &BackupJob{}
		if err := rows.Scan(
			&job.ID, &job.UserID, &job.SrcNodeID, &job.DstNodeID, &job.Trigger, &job.Status,
			&job.DataVersion, &job.Bytes, &job.FileCount, &job.Error, &job.StartedAt,
			&job.FinishedAt, &job.CreatedAt,
		); err != nil {
			return BackupPage{}, err
		}
		if len(page.Jobs) == params.Limit {
			page.HasMore = true
			break
		}
		page.Jobs = append(page.Jobs, job)
		page.NextCursor = job.ID
	}
	if err := rows.Err(); err != nil {
		return BackupPage{}, err
	}
	if !page.HasMore {
		page.NextCursor = 0
	}
	return page, nil
}
