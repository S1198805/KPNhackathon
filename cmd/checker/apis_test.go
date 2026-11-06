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
	"sync"
	"testing"
	"time"
)

func sampleAPI(t *testing.T, removed, user string, count int64) apiRequestObject {
	t.Helper()
	var p apiRequestObject
	body := fmt.Sprintf(`{"metadata":{"name":"flowschemas.v1beta3.flowcontrol.apiserver.k8s.io"},"status":{"removedInRelease":%q,"requestCount":%d,"currentHour":{"requestCount":%d,"byNode":[{"byUser":[{"username":%q,"requestCount":%d}]}]},"last24h":[{"requestCount":%d,"byNode":[{"byUser":[{"username":%q,"requestCount":%d}]}]}]}}`, removed, count, count, user, count, count, user, count)
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func hasAPIReason(r apiReport, reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
func TestAPIAssessment(t *testing.T) {
	for _, tc := range []struct {
		name, target, removed, user, want, reason string
		count                                     int64
		complete                                  bool
	}{
		{"removed at target", "1.32", "1.32", "system:serviceaccount:testapp:old-client", "blocker", "RemovedAPIClientObserved", 5, true},
		{"removed before target", "1.33", "1.32", "app", "blocker", "RemovedAPIClientObserved", 5, true},
		{"future removal", "1.31", "1.32", "app", "warning", "DeprecatedAPIObserved", 5, true},
		{"numeric ordering", "1.10", "1.9", "app", "blocker", "RemovedAPIClientObserved", 5, true},
		{"missing target", "", "1.32", "app", "unknown", "TargetKubernetesNotConfigured", 5, false},
		{"openshift is not kubernetes version", "4.23", "1.32", "app", "unknown", "TargetKubernetesNotConfigured", 5, false},
		{"bad target", "1.32.1", "1.32", "app", "unknown", "TargetKubernetesNotConfigured", 5, false},
		{"no use", "1.32", "1.32", "app", "ok", "", 0, true},
		{"not scheduled for removal", "1.32", "", "app", "ok", "", 5, true},
		{"unknown source", "1.32", "1.32", "", "unknown", "ClientAttributionIncomplete", 5, false},
		{"unrecognized removal", "1.32", "soon", "app", "unknown", "InvalidRemovalVersion", 5, false},
		{"system scanner", "1.32", "1.32", "system:kube-controller-manager", "warning", "SystemScannerRequestsObserved", 5, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := assessAPIs([]apiRequestObject{sampleAPI(t, tc.removed, tc.user, tc.count)}, tc.target)
			if r.Status != tc.want || r.Complete != tc.complete || !r.Success || (tc.reason != "" && !hasAPIReason(r, tc.reason)) {
				t.Fatalf("unexpected: %+v", r)
			}
			if len(r.APIs) > 0 && len(r.APIs[0].Clients) > 1 {
				t.Fatal("current hour double counted clients")
			}
		})
	}
	for _, user := range []string{"system:serviceaccount:kube-system:generic-garbage-collector", "system:serviceaccount:kube-system:namespace-controller", "system:kube-controller-manager", "system:cluster-policy-controller"} {
		r := assessAPIs([]apiRequestObject{sampleAPI(t, "1.32", user, 1)}, "1.32")
		if r.Status == "blocker" || !hasAPIReason(r, "SystemScannerRequestsObserved") {
			t.Fatal(user, r)
		}
	}
	// System-like client names outside the documented exception list must not be ignored.
	r := assessAPIs([]apiRequestObject{sampleAPI(t, "1.32", "system:serviceaccount:testapp:controller", 1)}, "1.32")
	if r.Status != "blocker" {
		t.Fatal(r)
	}
	r = assessAPIs(nil, "1.32")
	if r.Status != "unknown" || r.Complete || !r.Success || !hasAPIReason(r, "NoObservationData") {
		t.Fatal(r)
	}
	p := sampleAPI(t, "1.32", "app", 1)
	p.Status.RequestCount = nil
	r = assessAPIs([]apiRequestObject{p}, "1.32")
	if r.Complete || !hasAPIReason(r, "InvalidRequestStatus") {
		t.Fatal(r)
	}
}
func TestAPIMixedClientsAndCurrentHour(t *testing.T) {
	p := sampleAPI(t, "1.32", "system:kube-controller-manager", 3)
	p.Status.Last24h[0].ByNode[0].ByUser = append(p.Status.Last24h[0].ByNode[0].ByUser, apiUser{Username: "app", RequestCount: 1})
	r := assessAPIs([]apiRequestObject{p}, "1.32")
	if r.Status != "blocker" || len(r.APIs[0].Clients) != 1 || len(r.APIs[0].IgnoredClients) != 1 {
		t.Fatal(r)
	}
	p = sampleAPI(t, "1.32", "app", 3)
	*p.Status.RequestCount = 0
	r = assessAPIs([]apiRequestObject{p}, "1.32")
	if r.Status != "blocker" {
		t.Fatal("current hour use lost", r)
	}
	// A 24h count of 3 and current-hour count of 3 must remain 3, not 6.
	r = assessAPIs([]apiRequestObject{sampleAPI(t, "1.32", "app", 3)}, "1.32")
	rec := httptest.NewRecorder()
	apiMetrics(rec, r)
	if !strings.Contains(rec.Body.String(), `upgrade_readiness_deprecated_api_requests_24h{api="flowschemas.v1beta3.flowcontrol.apiserver.k8s.io",removed_in="1.32"} 3`) {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "app") {
		t.Fatal("client label should not be exported in metrics")
	}
}
func TestAPIReadAndIndependentFailure(t *testing.T) {
	valid, _ := json.Marshal(struct {
		Items []apiRequestObject `json:"items"`
	}{[]apiRequestObject{sampleAPI(t, "1.32", "app", 1)}})
	for _, tc := range []struct {
		name string
		code int
		body string
		err  bool
	}{
		{"valid", 200, string(valid), false}, {"empty observations", 200, `{"items":[]}`, false},
		{"forbidden", 403, `{}`, true}, {"missing list", 200, `{}`, true}, {"malformed", 200, `broken`, true},
		{"unnamed", 200, `{"items":[{}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			if e := os.WriteFile(token, []byte("private-test-token"), 0600); e != nil {
				t.Fatal(e)
			}
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/apis/apiserver.openshift.io/v1/apirequestcounts" || r.Header.Get("Authorization") != "Bearer private-test-token" {
					t.Error("invalid request")
				}
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()
			result, err := readAPIs(context.Background(), api.Client(), api.URL, token, "1.32")
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			app := &application{}
			app.record([]nodeResult{{Name: "crc", Ready: "True"}}, nil)
			app.operators.record(assessOperators(nil, "4.22.14", nil), nil)
			app.pdbs.record(assessPDBs(nil, nil), nil)
			app.apis.record(result, err)
			rec := httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, `upgrade_readiness_node_ready{node="crc"} 1`) || !strings.Contains(body, `upgrade_readiness_check_success{check="pdbs"} 1`) {
				t.Fatal("independent results lost", body)
			}
			if strings.Contains(body, "private-test-token") {
				t.Fatal("token leaked")
			}
			if tc.err {
				if !strings.Contains(body, `upgrade_readiness_check_success{check="apis"} 0`) || strings.Contains(body, "upgrade_readiness_api_requestcounts_total") {
					t.Fatal(body)
				}
			} else if !strings.Contains(body, `upgrade_readiness_check_success{check="apis"} 1`) {
				t.Fatal(body)
			}
			// Prometheus families must each have one TYPE and contiguous samples.
			seen := map[string]bool{}
			current := ""
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "# TYPE ") {
					name := strings.Fields(line)[2]
					if seen[name] {
						t.Fatal("duplicate TYPE", name)
					}
					seen[name] = true
					current = name
					continue
				}
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				name := strings.FieldsFunc(line, func(r rune) bool { return r == '{' || r == ' ' })[0]
				if current != name {
					t.Fatalf("noncontiguous family %s after %s", name, current)
				}
			}
			rec = httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/report", nil))
			var data struct {
				Status string
				Checks map[string]json.RawMessage
			}
			if e := json.Unmarshal(rec.Body.Bytes(), &data); e != nil {
				t.Fatal(e)
			}
			if len(data.Checks) != 4 {
				t.Fatal(rec.Body.String())
			}
			if tc.err && data.Status != "unknown" {
				t.Fatal(rec.Body.String())
			}
		})
	}
}
func TestAPIStaleAndConcurrent(t *testing.T) {
	s := &apiState{}
	s.record(assessAPIs([]apiRequestObject{sampleAPI(t, "", "app", 1)}, "1.32"), nil)
	s.mu.Lock()
	s.result.CheckedAt = time.Now().Unix() - 121
	s.mu.Unlock()
	r, last := s.snapshot()
	if r.Success || r.Complete || r.Status != "unknown" || last == 0 {
		t.Fatal(r)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() { s.record(assessAPIs(nil, ""), nil); s.snapshot() })
	}
	wg.Wait()
}
