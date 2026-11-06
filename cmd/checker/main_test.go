package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNodeAssessment(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		httpStatus       int
		wantErr          bool
	}{
		{"ready", `{"items":[{"metadata":{"name":"crc"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`, "True", 200, false},
		{"not ready", `{"items":[{"metadata":{"name":"crc"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}]}`, "False", 200, false},
		{"missing condition", `{"items":[{"metadata":{"name":"crc"}}]}`, "Unknown", 200, false},
		{"empty inventory", `{"items":[]}`, "", 200, true},
		{"forbidden", `{}`, "", 403, true},
		{"malformed response", `not json`, "", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
				t.Fatal(err)
			}
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/nodes" || r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("incorrect authenticated API request")
				}
				w.WriteHeader(tc.httpStatus)
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()
			nodes, err := readNodes(context.Background(), api.Client(), api.URL, token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			app := &application{}
			app.record(nodes, err)
			rec := httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			body := rec.Body.String()
			if tc.wantErr {
				if !strings.Contains(body, `upgrade_readiness_check_success{check="nodes"} 0`) || strings.Contains(body, "upgrade_readiness_nodes_total") {
					t.Fatal("failed scan exposed healthy-looking results")
				}
			} else {
				if nodes[0].Ready != tc.want {
					t.Fatalf("Ready=%s", nodes[0].Ready)
				}
				r, _ := app.snapshot()
				if (r.Status == "ok") != (tc.want == "True") {
					t.Fatalf("status=%s", r.Status)
				}
			}
		})
	}
}

func TestPaginationAndTokenRotation(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	expected := "first"
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expected {
			t.Error("token was not refreshed")
		}
		if r.URL.Query().Get("continue") == "" {
			fmt.Fprint(w, `{"metadata":{"continue":"next"},"items":[{"metadata":{"name":"a"}}]}`)
		} else {
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"b"}}]}`)
		}
	}))
	defer api.Close()
	for _, value := range []string{"first", "rotated"} {
		expected = value
		if err := os.WriteFile(token, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		nodes, err := readNodes(context.Background(), api.Client(), api.URL, token)
		if err != nil || len(nodes) != 2 {
			t.Fatalf("pagination: %v %v", nodes, err)
		}
	}
}

func TestStaleAndConcurrentAccess(t *testing.T) {
	app := &application{result: report{Status: "ok", CheckedAt: time.Now().Unix() - 121, Nodes: []nodeResult{{Name: "crc", Ready: "True"}}}}
	r, _ := app.snapshot()
	if r.Status != "unknown" || len(r.Nodes) != 0 {
		t.Fatal("stale results were retained as current")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			app.record([]nodeResult{{Name: "crc", Ready: "True"}}, nil)
		}
	}()
	for i := 0; i < 100; i++ {
		app.handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/metrics", nil))
	}
	<-done
}