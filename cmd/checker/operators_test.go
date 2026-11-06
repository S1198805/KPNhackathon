package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testOperator(conditions []condition) operatorObject {
	var op operatorObject
	op.Metadata.Name = "network"
	op.Status.Conditions = conditions
	return op
}
func TestOperatorAssessment(t *testing.T) {
	for _, tc := range []struct {
		name, available, degraded, progressing, upgradeable, want string
		complete                                                  bool
	}{
		{"healthy with optional upgradeability absent", "True", "False", "False", "", "ok", true},
		{"unavailable", "False", "False", "False", "True", "blocker", true},
		{"degraded", "True", "True", "False", "True", "blocker", true},
		{"progressing", "True", "False", "True", "True", "warning", true},
		{"minor upgrade blocked", "True", "False", "False", "False", "blocker", true},
		{"missing available", "", "False", "False", "True", "unknown", false},
		{"unknown degraded", "True", "Unknown", "False", "True", "unknown", false},
		{"unknown upgradeability", "True", "False", "False", "Unknown", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conditions := []condition{}
			for _, c := range []condition{{Type: "Available", Status: tc.available}, {Type: "Degraded", Status: tc.degraded}, {Type: "Progressing", Status: tc.progressing}, {Type: "Upgradeable", Status: tc.upgradeable}} {
				if c.Status != "" {
					conditions = append(conditions, c)
				}
			}
			r := assessOperators([]operatorObject{testOperator(conditions)}, "4.20.1", nil)
			if r.Status != tc.want || r.Complete != tc.complete || !r.Success {
				t.Fatalf("unexpected report: %+v", r)
			}
			if tc.name == "minor upgrade blocked" && !strings.Contains(r.Findings[0].Advice, "patchupdate") {
				t.Fatal("minor/patch distinction missing")
			}
		})
	}
	healthy := testOperator([]condition{{Type: "Available", Status: "True"}, {Type: "Degraded", Status: "False"}})
	r := assessOperators([]operatorObject{healthy}, "4.20.1", []condition{{Type: "Upgradeable", Status: "False", Reason: "AdminAckRequired", Message: "ack needed"}})
	if r.Status != "blocker" || r.Findings[0].Resource != "ClusterVersion/version" || r.Findings[0].Reason != "AdminAckRequired" {
		t.Fatalf("cluster upgrade blocker lost: %+v", r)
	}
}

func TestOperatorAPIAndIndependentFailure(t *testing.T) {
	for _, tc := range []struct {
		name               string
		code               int
		operators, version string
		wantErr            bool
	}{
		{"success", 200, `{"items":[{"metadata":{"name":"network"},"status":{"conditions":[{"type":"Available","status":"True"},{"type":"Degraded","status":"False"}]}}]}`, `{"status":{"desired":{"version":"4.20.1"}}}`, false},
		{"forbidden", 403, `{}`, `{}`, true},
		{"empty", 200, `{"items":[]}`, `{}`, true},
		{"bad json", 200, `not json`, `{}`, true},
		{"missing version", 200, `{"items":[{"metadata":{"name":"network"}}]}`, `{}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
				t.Fatal(err)
			}
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing authentication")
				}
				w.WriteHeader(tc.code)
				if strings.Contains(r.URL.Path, "clusterversions/") {
					fmt.Fprint(w, tc.version)
				} else {
					fmt.Fprint(w, tc.operators)
				}
			}))
			defer api.Close()
			report, err := readOperators(context.Background(), api.Client(), api.URL, token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected API error: %v", err)
			}
			app := &application{}
			app.record([]nodeResult{{Name: "crc", Ready: "True"}}, nil)
			app.operators.record(report, err)
			rec := httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, `upgrade_readiness_node_ready{node="crc"} 1`) {
				t.Fatal("node results lost")
			}
			if tc.wantErr && (!strings.Contains(body, `upgrade_readiness_check_success{check="operators"} 0`) || strings.Contains(body, "upgrade_readiness_operators_total")) {
				t.Fatal("failed Operator scan looks healthy")
			}
			if strings.Contains(body, "test-token") {
				t.Fatal("token leaked")
			}
			for _, metric := range []string{"upgrade_readiness_check_success", "upgrade_readiness_findings", "upgrade_readiness_last_success_timestamp_seconds"} {
				if strings.Count(body, "# TYPE "+metric+" gauge") != 1 {
					t.Fatal("duplicate metric family declaration")
				}
			}
			rec = httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/report", nil))
			var data struct {
				Status string
				Checks map[string]json.RawMessage
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			if len(data.Checks) != 4 || (tc.wantErr && data.Status != "unknown") {
				t.Fatalf("invalid combined report: %s", rec.Body.String())
			}
		})
	}
}

func TestOperatorStaleness(t *testing.T) {
	app := &application{}
	app.record([]nodeResult{{Name: "crc", Ready: "True"}}, nil)
	app.operators.result = operatorReport{Status: "ok", Success: true, Complete: true, CheckedAt: time.Now().Unix() - 121}
	r, _ := app.operators.snapshot()
	if r.Status != "unknown" || r.Success || r.Complete {
		t.Fatal("stale Operator results look current")
	}
}
