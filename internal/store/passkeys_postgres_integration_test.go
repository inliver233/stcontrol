package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresPasskeys(t *testing.T) {
	dsn, cleanupSchema := newPostgresIntegrationSchema(t)
	defer cleanupSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("settings start switched off and validate changes", func(t *testing.T) {
		settings, err := st.GetPasskeySettings(ctx)
		if err != nil || settings.Enabled || !settings.AllowRegistration || !settings.ShowOnLoginPage ||
			settings.MaxPerUser != 10 || settings.UserVerification != "preferred" || settings.LoginButtonText != "通行密钥登录" {
			t.Fatalf("defaults=%+v err=%v", settings, err)
		}
		for _, bad := range []PasskeySettings{
			{MaxPerUser: 0, UserVerification: "preferred", LoginButtonText: "x"},
			{MaxPerUser: 11, UserVerification: "preferred", LoginButtonText: "x"},
			{MaxPerUser: 3, UserVerification: "sometimes", LoginButtonText: "x"},
			{MaxPerUser: 3, UserVerification: "preferred", LoginButtonText: "   "},
			{MaxPerUser: 3, UserVerification: "preferred", LoginButtonText: strings.Repeat("长", 25)},
			{MaxPerUser: 3, UserVerification: "preferred", LoginButtonText: "x", LoginHintText: strings.Repeat("长", 81)},
		} {
			if _, err := st.UpdatePasskeySettings(ctx, bad, 0, now); !errors.Is(err, ErrInvalidPasskeyInput) {
				t.Fatalf("invalid settings %+v accepted: %v", bad, err)
			}
		}
		saved, err := st.UpdatePasskeySettings(ctx, PasskeySettings{
			Enabled: true, AllowRegistration: true, ShowOnLoginPage: true, MaxPerUser: 2,
			UserVerification: "required", LoginButtonText: "  刷指纹登录 ", LoginHintText: "",
		}, 0, now)
		if err != nil || saved.LoginButtonText != "刷指纹登录" {
			t.Fatalf("save settings=%+v err=%v", saved, err)
		}
		if got, err := st.GetPasskeySettings(ctx); err != nil || !got.Enabled || got.MaxPerUser != 2 ||
			got.UserVerification != "required" || got.LoginButtonText != "刷指纹登录" || got.LoginHintText != "" {
			t.Fatalf("stored settings=%+v err=%v", got, err)
		}
	})

	alice := insertIntegrationGlobalUser(t, st, "passkey-alice")
	bob := insertIntegrationGlobalUser(t, st, "passkey-bob")

	t.Run("ceremonies are single use and bound to purpose and user", func(t *testing.T) {
		const login = "60000000-0000-4000-8000-000000000001"
		const register = "60000000-0000-4000-8000-000000000002"
		const expired = "60000000-0000-4000-8000-000000000003"
		if err := st.CreatePasskeyCeremony(ctx, login, "login", 0, []byte(`{"challenge":"a"}`), now.Add(time.Minute), now); err != nil {
			t.Fatalf("create login ceremony: %v", err)
		}
		if err := st.CreatePasskeyCeremony(ctx, register, "register", alice, []byte(`{"challenge":"b"}`), now.Add(time.Minute), now); err != nil {
			t.Fatalf("create register ceremony: %v", err)
		}
		if err := st.CreatePasskeyCeremony(ctx, expired, "login", 0, []byte(`{}`), now.Add(time.Second), now); err != nil {
			t.Fatalf("create short ceremony: %v", err)
		}
		const spare = "60000000-0000-4000-8000-000000000004"
		for _, bad := range []struct {
			id, purpose string
			user        int64
			expires     time.Time
		}{
			{"not-a-uuid", "login", 0, now.Add(time.Minute)},
			{spare, "register", 0, now.Add(time.Minute)},
			{spare, "login", alice, now.Add(time.Minute)},
			{spare, "unknown", 0, now.Add(time.Minute)},
			{spare, "login", 0, now},
		} {
			if err := st.CreatePasskeyCeremony(ctx, bad.id, bad.purpose, bad.user, []byte(`{}`), bad.expires, now); !errors.Is(err, ErrInvalidPasskeyInput) {
				t.Fatalf("invalid ceremony %+v accepted: %v", bad, err)
			}
		}
		// Wrong purpose or user never consumes.
		if _, err := st.ConsumePasskeyCeremony(ctx, register, "register", bob, now); !errors.Is(err, ErrPasskeyCeremonyFailed) {
			t.Fatalf("other user's ceremony consumed: %v", err)
		}
		if _, err := st.ConsumePasskeyCeremony(ctx, register, "login", 0, now); !errors.Is(err, ErrPasskeyCeremonyFailed) {
			t.Fatalf("ceremony consumed for the wrong purpose: %v", err)
		}
		if session, err := st.ConsumePasskeyCeremony(ctx, register, "register", alice, now); err != nil || !strings.Contains(string(session), `"b"`) {
			t.Fatalf("consume register: session=%s err=%v", session, err)
		}
		// Concurrent consumers: exactly one wins.
		var wins int
		var mu sync.Mutex
		var wait sync.WaitGroup
		for range 8 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if _, err := st.ConsumePasskeyCeremony(ctx, login, "login", 0, now); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wait.Wait()
		if wins != 1 {
			t.Fatalf("login ceremony consumed %d times", wins)
		}
		if _, err := st.ConsumePasskeyCeremony(ctx, expired, "login", 0, now.Add(2*time.Second)); !errors.Is(err, ErrPasskeyCeremonyFailed) {
			t.Fatalf("expired ceremony consumed: %v", err)
		}
	})

	var alicePasskeys []UserPasskey
	t.Run("passkeys respect the per-user limit and stay unique", func(t *testing.T) {
		add := func(user int64, id string, name string, limit int) (UserPasskey, error) {
			return st.AddUserPasskey(ctx, AddUserPasskeyParams{
				UserID: user, CredentialID: []byte(id), Credential: []byte(`{"id":"` + id + `"}`),
				Name: name, MaxPerUser: limit, Now: now,
			})
		}
		first, err := add(alice, "cred-a1", "  iPhone   · Safari ", 2)
		if err != nil || first.Name != "iPhone · Safari" {
			t.Fatalf("first passkey=%+v err=%v", first, err)
		}
		second, err := add(alice, "cred-a2", "", 2)
		if err != nil || second.Name != "通行密钥" {
			t.Fatalf("second passkey=%+v err=%v", second, err)
		}
		if _, err := add(alice, "cred-a3", "third", 2); !errors.Is(err, ErrPasskeyLimit) {
			t.Fatalf("third passkey over the limit: %v", err)
		}
		if _, err := add(bob, "cred-a1", "stolen", 10); !errors.Is(err, ErrPasskeyExists) {
			t.Fatalf("duplicate credential: %v", err)
		}
		long, err := add(bob, "cred-b1", strings.Repeat("名", 60), 10)
		if err != nil || len([]rune(long.Name)) != 40 {
			t.Fatalf("long name passkey=%+v err=%v", long, err)
		}
		alicePasskeys, err = st.ListUserPasskeys(ctx, alice)
		if err != nil || len(alicePasskeys) != 2 || alicePasskeys[0].ID != first.ID {
			t.Fatalf("alice passkeys=%+v err=%v", alicePasskeys, err)
		}
	})

	t.Run("sign-in lookup, counters and ownership", func(t *testing.T) {
		owner, err := st.GetPasskeyOwner(ctx, []byte("cred-a1"))
		if err != nil || owner == nil || owner.Passkey.UserID != alice || owner.UserUUID == "" {
			t.Fatalf("owner=%+v err=%v", owner, err)
		}
		if missing, err := st.GetPasskeyOwner(ctx, []byte("nope")); err != nil || missing != nil {
			t.Fatalf("missing owner=%+v err=%v", missing, err)
		}
		if err := st.RecordPasskeyLogin(ctx, owner.Passkey.ID, bob, []byte(`{}`), now); !errors.Is(err, ErrPasskeyNotFound) {
			t.Fatalf("login recorded for the wrong user: %v", err)
		}
		if err := st.RecordPasskeyLogin(ctx, owner.Passkey.ID, alice, []byte(`{"id":"cred-a1","signCount":5}`), now.Add(time.Minute)); err != nil {
			t.Fatalf("record login: %v", err)
		}
		if err := st.RecordPasskeyLoginFailure(ctx, "unknown_credential"); err != nil {
			t.Fatalf("record failure: %v", err)
		}
		updated, err := st.GetPasskeyOwner(ctx, []byte("cred-a1"))
		if err != nil || updated.Passkey.LastUsedAt == nil || !strings.Contains(string(updated.Passkey.Credential), `"signCount": 5`) {
			t.Fatalf("updated=%+v err=%v", updated, err)
		}
		// Users can only rename and delete their own passkeys.
		if _, err := st.RenameUserPasskey(ctx, bob, owner.Passkey.ID, "mine now"); !errors.Is(err, ErrPasskeyNotFound) {
			t.Fatalf("rename someone else's passkey: %v", err)
		}
		renamed, err := st.RenameUserPasskey(ctx, alice, owner.Passkey.ID, "我的手机")
		if err != nil || renamed.Name != "我的手机" {
			t.Fatalf("rename=%+v err=%v", renamed, err)
		}
		if err := st.DeletePasskey(ctx, owner.Passkey.ID, bob, 0); !errors.Is(err, ErrPasskeyNotFound) {
			t.Fatalf("delete someone else's passkey: %v", err)
		}
		if err := st.DeletePasskey(ctx, owner.Passkey.ID, alice, 7); !errors.Is(err, ErrInvalidPasskeyInput) {
			t.Fatalf("ambiguous delete accepted: %v", err)
		}
	})

	t.Run("administrator overview and removals", func(t *testing.T) {
		overview, err := st.GetPasskeyOverview(ctx, 21, now)
		if err != nil || overview.UsersWithPasskeys != 2 || overview.TotalPasskeys != 3 || len(overview.Days) != 21 {
			t.Fatalf("overview=%+v err=%v", overview, err)
		}
		today := overview.Days[len(overview.Days)-1]
		if today.Day != now.Format("2006-01-02") || today.Registered != 3 || today.LoginSuccess != 1 || today.LoginFailure != 1 {
			t.Fatalf("today=%+v", today)
		}
		if err := st.DeletePasskey(ctx, alicePasskeys[1].ID, 0, 1); err != nil {
			t.Fatalf("admin delete: %v", err)
		}
		var bobUUID string
		if err := st.DB.QueryRow(`SELECT uuid::text FROM global_users WHERE id=$1`, bob).Scan(&bobUUID); err != nil {
			t.Fatal(err)
		}
		if removed, err := st.DeleteAllUserPasskeys(ctx, bobUUID, 1); err != nil || removed != 1 {
			t.Fatalf("delete all of bob: removed=%d err=%v", removed, err)
		}
		if removed, err := st.DeleteAllUserPasskeys(ctx, bobUUID, 1); err != nil || removed != 0 {
			t.Fatalf("delete all again: removed=%d err=%v", removed, err)
		}
		overview, err = st.GetPasskeyOverview(ctx, 21, now)
		if err != nil || overview.UsersWithPasskeys != 1 || overview.TotalPasskeys != 1 || overview.Users[0].Passkeys[0].Name != "我的手机" {
			t.Fatalf("overview after removals=%+v err=%v", overview, err)
		}
		var audits int
		if err := st.DB.QueryRow(`
			SELECT count(*) FROM audit_events WHERE target_type='passkey' AND action='passkey-removed'`).Scan(&audits); err != nil || audits != 2 {
			t.Fatalf("removal audits=%d err=%v", audits, err)
		}
	})

	t.Run("passkeys go with their user", func(t *testing.T) {
		if _, err := st.DB.Exec(`DELETE FROM global_users WHERE id=$1`, alice); err != nil {
			t.Skipf("global user cannot be deleted directly in this schema: %v", err)
		}
		if owner, err := st.GetPasskeyOwner(ctx, []byte("cred-a1")); err != nil || owner != nil {
			t.Fatalf("passkey survived its user: %+v %v", owner, err)
		}
	})
}
