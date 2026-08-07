package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi/v5"
	"stcontrol/internal/store"
)

func TestIdentityRecoveryRequestDigestIsStableKeyedAndPrincipalBound(t *testing.T) {
	t.Parallel()
	input := identityRecoveryDigestInput{
		OperationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		UserUUID:    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		AdminID:     5,
		Password:    "new-password",
	}
	server := &Server{secretKey: bytes.Repeat([]byte{1}, 32)}
	first, err := server.identityRecoveryRequestDigest(input)
	second, err2 := server.identityRecoveryRequestDigest(input)
	if err != nil || err2 != nil || !bytes.Equal(first, second) || len(first) != 32 {
		t.Fatalf("first=%x second=%x err=%v err2=%v", first, second, err, err2)
	}
	input.AdminID++
	adminChanged, _ := server.identityRecoveryRequestDigest(input)
	input.AdminID--
	input.Password = "other-password"
	passwordChanged, _ := server.identityRecoveryRequestDigest(input)
	otherKey, _ := (&Server{secretKey: bytes.Repeat([]byte{2}, 32)}).
		identityRecoveryRequestDigest(input)
	if bytes.Equal(first, adminChanged) || bytes.Equal(first, passwordChanged) || bytes.Equal(passwordChanged, otherKey) {
		t.Fatal("recovery digest was not bound to admin, password, and controller secret")
	}
}

func TestAdminIdentityRecoveryRejectsInvalidGlobalUUIDBeforeHashing(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{Store: &store.Store{DB: db}, secretKey: bytes.Repeat([]byte{1}, 32)}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/alice/identity-recovery",
		bytes.NewBufferString(`{"operation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","password":"new-password"}`))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("uuid", "alice")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	req = req.WithContext(context.WithValue(ctx, ctxKey("stcontrol-session"), &session{
		AdminID: 5, Username: "admin-one", IsAdmin: true,
	}))
	recorder := httptest.NewRecorder()
	server.handleAdminRecoverUserIdentity(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
