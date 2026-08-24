package controller

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"stcontrol/internal/store"
)

func TestAdminIdentityRecoveryHTTPRoundTripAndReplayPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("Admin identity recovery PostgreSQL integration is disabled in short mode")
	}
	dsn, cleanupSchema := newControllerBackupPostgresSchema(t)
	t.Cleanup(cleanupSchema)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	created, err := st.BootstrapAdmin(ctx, "recovery-admin", "test-password-hash", time.Now().UTC())
	if err != nil || !created {
		t.Fatalf("bootstrap recovery admin: created=%v err=%v", created, err)
	}
	var adminID int64
	if err := st.DB.QueryRowContext(ctx, `SELECT id FROM admins WHERE username='recovery-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	user := &store.User{
		Username: "recovery-user", DisplayName: "Recovery User", AuthProvider: "linuxdo",
		OAuthID: sql.NullString{String: "recovery-subject", Valid: true}, Status: "active",
	}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	server := New(nil, st, bytes.Repeat([]byte{0x4a}, 32))
	sess := &session{AdminID: adminID, Username: "recovery-admin", IsAdmin: true}
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

	unauthorized := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(unauthorized,
		identityRecoveryRequest(t, user.UUID, operationID, "new-secure-password", nil))
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("unauthorized recovery status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	shortPassword := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(shortPassword,
		identityRecoveryRequest(t, user.UUID, operationID, "short", sess))
	if shortPassword.Code != http.StatusBadRequest {
		t.Fatalf("short-password recovery status=%d body=%s", shortPassword.Code, shortPassword.Body.String())
	}

	first := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(first,
		identityRecoveryRequest(t, user.UUID, operationID, "new-secure-password", sess))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"identity_recovered":true`) ||
		!strings.Contains(first.Body.String(), `"replayed":false`) {
		t.Fatalf("first recovery status=%d body=%s", first.Code, first.Body.String())
	}
	replay := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(replay,
		identityRecoveryRequest(t, user.UUID, operationID, "new-secure-password", sess))
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) {
		t.Fatalf("replayed recovery status=%d body=%s", replay.Code, replay.Body.String())
	}
	conflict := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(conflict,
		identityRecoveryRequest(t, user.UUID, operationID, "different-secure-password", sess))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflicting replay status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	var passwordIdentities int
	if err := st.DB.QueryRowContext(ctx, `
		SELECT count(*) FROM auth_identities WHERE user_id=$1 AND provider='password' AND status='active'`, user.GlobalID).
		Scan(&passwordIdentities); err != nil || passwordIdentities != 1 {
		t.Fatalf("password identities=%d err=%v", passwordIdentities, err)
	}
}

func identityRecoveryRequest(
	t *testing.T,
	userUUID, operationID, password string,
	sess *session,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+userUUID+"/identity-recovery",
		strings.NewReader(`{"operation_id":"`+operationID+`","password":"`+password+`"}`))
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("uuid", userUUID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
	if sess != nil {
		request = request.WithContext(context.WithValue(request.Context(), ctxKey("stcontrol-session"), sess))
	}
	return request
}
