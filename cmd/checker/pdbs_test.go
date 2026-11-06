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

func samplePDB(t *testing.T, allowed int) pdbObject {
	t.Helper()
	var p pdbObject
	text := fmt.Sprintf(`{"metadata":{"name":"web","namespace":"testapp","generation":2},"spec":{"selector":{"matchLabels":{"app":"web"}}},"status":{"observedGeneration":2,"disruptionsAllowed":%d,"currentHealthy":2,"desiredHealthy":1,"expectedPods":2}}`, allowed)
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func samplePod() podObject {
	var p podObject
	p.Metadata.Name = "web-1"
	p.Metadata.Namespace = "testapp"
	p.Metadata.Labels = map[string]string{"app": "web"}
	p.Status.Phase = "Running"
	p.Status.Conditions = []condition{{Type: "Ready", Status: "True"}}
	return p
}
func hasPDBReason(r pdbReport, reason string) bool {
	for _, f := range r.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
func TestPDBAssessment(t *testing.T) {
	for _, tc := range []struct {
		name, want, reason string
		mutate             func(*pdbObject, *podObject)
	}{
		{"allowed", "ok", "", func(*pdbObject, *podObject) {}},
		{"zero budget", "blocker", "NoDisruptionsAllowed", func(p *pdbObject, _ *podObject) { *p.Status.DisruptionsAllowed = 0 }},
		{"stale generation", "unknown", "StatusNotCurrent", func(p *pdbObject, _ *podObject) { *p.Status.ObservedGeneration = 1 }},
		{"missing status", "unknown", "StatusNotCurrent", func(p *pdbObject, _ *podObject) { p.Status.DisruptionsAllowed = nil }},
		{"controller error", "unknown", "StatusNotCurrent", func(p *pdbObject, _ *podObject) { p.Status.Conditions = []condition{{Reason: "SyncFailed"}} }},
		{"no match", "warning", "NoMatchingPods", func(_ *pdbObject, p *podObject) { p.Metadata.Labels["app"] = "other" }},
		{"namespace isolation", "warning", "NoMatchingPods", func(_ *pdbObject, p *podObject) { p.Metadata.Namespace = "other" }},
		{"null selector", "warning", "NoMatchingPods", func(p *pdbObject, _ *podObject) { p.Spec.Selector = nil }},
		{"empty selector", "warning", "NamespaceWideSelector", func(p *pdbObject, _ *podObject) { p.Spec.Selector = &labelSelector{} }},
		{"unknown expression", "unknown", "InvalidSelector", func(p *pdbObject, _ *podObject) {
			json.Unmarshal([]byte(`{"matchExpressions":[{"key":"app","operator":"NewOperator"}]}`), &p.Spec.Selector)
		}},
		{"daemonset no healthy drain blocker", "ok", "", func(p *pdbObject, pod *podObject) {
			*p.Status.DisruptionsAllowed = 0
			json.Unmarshal([]byte(`{"ownerReferences":[{"kind":"DaemonSet"}]}`), &pod.Metadata)
		}},
		{"unhealthy pod no healthy drain blocker", "ok", "", func(p *pdbObject, pod *podObject) { *p.Status.DisruptionsAllowed = 0; pod.Status.Conditions = nil }},
		{"terminated pod", "warning", "NoMatchingPods", func(_ *pdbObject, pod *podObject) { pod.Status.Phase = "Succeeded" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := samplePDB(t, 1)
			pod := samplePod()
			tc.mutate(&p, &pod)
			r := assessPDBs([]pdbObject{p}, []podObject{pod})
			if r.Status != tc.want || !r.Success || (tc.reason != "" && !hasPDBReason(r, tc.reason)) {
				t.Fatalf("unexpected %+v", r)
			}
			if (tc.want == "unknown") == r.Complete {
				t.Fatalf("incorrect completeness: %+v", r)
			}
		})
	}
	a, b := samplePDB(t, 1), samplePDB(t, 1)
	b.Metadata.Name = "another"
	r := assessPDBs([]pdbObject{a, b}, []podObject{samplePod()})
	if !hasPDBReason(r, "OverlappingPDBs") || r.Status != "blocker" {
		t.Fatalf("missed overlap: %+v", r)
	}
	r = assessPDBs(nil, nil)
	if !r.Success || !r.Complete || r.Status != "ok" || len(r.PDBs) != 0 {
		t.Fatal(r)
	}
}
func TestPDBExpressions(t *testing.T) {
	for _, tc := range []struct {
		selector string
		labels   map[string]string
		want     bool
	}{
		{`{"matchExpressions":[{"key":"app","operator":"In","values":["web"]}]}`, map[string]string{"app": "web"}, true},
		{`{"matchExpressions":[{"key":"app","operator":"In","values":["web"]}]}`, nil, false},
		{`{"matchExpressions":[{"key":"app","operator":"NotIn","values":["web"]}]}`, nil, true},
		{`{"matchExpressions":[{"key":"app","operator":"NotIn","values":["web"]}]}`, map[string]string{"app": "web"}, false},
		{`{"matchExpressions":[{"key":"app","operator":"Exists"}]}`, map[string]string{"app": ""}, true},
		{`{"matchExpressions":[{"key":"app","operator":"DoesNotExist"}]}`, nil, true},
		{`{"matchLabels":{"app":""}}`, nil, false},
	} {
		var s labelSelector
		if err := json.Unmarshal([]byte(tc.selector), &s); err != nil {
			t.Fatal(err)
		}
		if !s.valid() || s.matches(tc.labels) != tc.want {
			t.Fatal(tc)
		}
	}
}
func TestPDBAPI(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    int
		body    string
		wantErr bool
	}{
		{"empty valid", 200, `{"items":[]}`, false}, {"forbidden", 403, `{}`, true}, {"missing items", 200, `{}`, true}, {"bad JSON", 200, `bad`, true}, {"no resource name", 200, `{"items":[{}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			os.WriteFile(token, []byte("pdb-token"), 0600)
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer pdb-token" {
					t.Error("missing auth")
				}
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer api.Close()
			result, err := readPDBs(context.Background(), api.Client(), api.URL, token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected %v", err)
			}
			app := &application{}
			app.record([]nodeResult{{Name: "crc", Ready: "True"}}, nil)
			app.operators.record(assessOperators(nil, "4.22.14", nil), nil)
			app.pdbs.record(result, err)
			rec := httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			body := rec.Body.String()
			if !strings.Contains(body, `upgrade_readiness_node_ready{node="crc"} 1`) || strings.Contains(body, "pdb-token") {
				t.Fatal(body)
			}
			if tc.wantErr {
				if !strings.Contains(body, `upgrade_readiness_check_success{check="pdbs"} 0`) || strings.Contains(body, "upgrade_readiness_pdbs_total") {
					t.Fatal(body)
				}
			} else if !strings.Contains(body, "upgrade_readiness_pdbs_total 0") {
				t.Fatal(body)
			}
			for _, family := range []string{"assessment_complete", "findings", "check_success"} {
				if strings.Count(body, "# TYPE upgrade_readiness_"+family+" gauge") != 1 {
					t.Fatal("duplicate family", body)
				}
			}
			rec = httptest.NewRecorder()
			app.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/report", nil))
			var combined struct {
				Status string
				Checks map[string]json.RawMessage
			}
			if e := json.Unmarshal(rec.Body.Bytes(), &combined); e != nil {
				t.Fatal(e)
			}
			if len(combined.Checks) != 4 || (tc.wantErr && combined.Status != "unknown") {
				t.Fatal(rec.Body.String())
			}
		})
	}
}
func TestPDBPaginationAndStale(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("token"), 0600)
	calls := 0
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("continue") == "" {
			fmt.Fprint(w, `{"metadata":{"continue":"next"},"items":[]}`)
		} else {
			fmt.Fprint(w, `{"items":[]}`)
		}
	}))
	defer api.Close()
	_, err := readPDBs(context.Background(), api.Client(), api.URL, token)
	if err != nil || calls != 4 {
		t.Fatalf("pagination %d: %v", calls, err)
	}
	s := &pdbState{}
	s.record(assessPDBs(nil, nil), nil)
	s.mu.Lock()
	s.result.CheckedAt = time.Now().Unix() - 121
	s.mu.Unlock()
	r, last := s.snapshot()
	if r.Success || r.Complete || r.Status != "unknown" || last == 0 {
		t.Fatal(r)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() { s.record(assessPDBs(nil, nil), nil); s.snapshot() })
	}
	wg.Wait()
}
