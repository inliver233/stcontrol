package controller

import (
	"net/http/httptest"
	"testing"
)

func TestParseAdminPageBoundsCursorAndLimit(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest("GET", "/api/admin/users?after=42&limit=100", nil)
	limit, cursor, err := parseAdminPage(request, "after")
	if err != nil || limit != 100 || cursor != 42 {
		t.Fatalf("limit=%d cursor=%d err=%v", limit, cursor, err)
	}
	for _, rawURL := range []string{
		"/api/admin/users?limit=101", "/api/admin/users?limit=0",
		"/api/admin/users?after=-1", "/api/admin/users?after=nope",
	} {
		request := httptest.NewRequest("GET", rawURL, nil)
		if _, _, err := parseAdminPage(request, "after"); err == nil {
			t.Fatalf("invalid page accepted: %s", rawURL)
		}
	}
}
