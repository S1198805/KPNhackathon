package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const credentials = "/var/run/secrets/kubernetes.io/serviceaccount/"

type nodeResult struct {
	Name   string `json:"name"`
	Ready  string `json:"ready"`
	Advice string `json:"advice,omitempty"`
}
type report struct {
	Status    string       `json:"status"`
	CheckedAt int64        `json:"checked_at_unix"`
	Error     string       `json:"error,omitempty"`
	Nodes     []nodeResult `json:"nodes"`
}
type application struct {
	mu          sync.RWMutex
	result      report
	lastSuccess int64
	operators   operatorState
	pdbs        pdbState
	apis        apiState
}

// Tokens are read for every scan because Kubernetes rotates them.
func readNodes(ctx context.Context, client *http.Client, baseURL, tokenPath string) ([]nodeResult, error) {
	token, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(token)) == "" {
		return nil, fmt.Errorf("ServiceAccount-token ontbreekt of is niet leesbaar")
	}
	nodes := []nodeResult{}
	continuation := ""
	for {
		query := url.Values{"limit": {"500"}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/nodes?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		req.Header.Set("Accept", "application/json")
		response, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("OpenShift API niet bereikbaar: %w", err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("OpenShift API geeft HTTP %d; controleer bij 401/403 de ServiceAccount en leesrechten", response.StatusCode)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Status struct {
					Conditions []struct{ Type, Status string } `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		err = json.NewDecoder(response.Body).Decode(&page)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("ongeldig API-antwoord: %w", err)
		}
		for _, item := range page.Items {
			if item.Metadata.Name == "" {
				return nil, fmt.Errorf("node zonder naam ontvangen")
			}
			n := nodeResult{Name: item.Metadata.Name, Ready: "Unknown"}
			for _, c := range item.Status.Conditions {
				if c.Type == "Ready" && (c.Status == "True" || c.Status == "False") {
					n.Ready = c.Status
				}
			}
			if n.Ready != "True" {
				n.Advice = "Onderzoek nodecondities en events, de kubelet en de netwerkverbinding met het control plane voordat je een upgrade plant."
			}
			nodes = append(nodes, n)
		}
		continuation = page.Metadata.Continue
		if continuation == "" {
			break
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("geen nodes ontvangen; nodegereedheid kan niet worden vastgesteld")
	}
	return nodes, nil
}

func (app *application) record(nodes []nodeResult, err error) {
	r := report{Status: "ok", CheckedAt: time.Now().Unix(), Nodes: nodes}
	if err != nil {
		r.Status, r.Error, r.Nodes = "error", err.Error(), []nodeResult{}
	} else {
		for _, n := range nodes {
			if n.Ready != "True" {
				r.Status = "blocker"
			}
		}
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	app.result = r
	if err == nil {
		app.lastSuccess = r.CheckedAt
	}
}

func (app *application) scan() {
	ca, err := os.ReadFile(credentials + "ca.crt")
	if err != nil {
		app.record(nil, fmt.Errorf("ServiceAccount CA-certificaat niet leesbaar"))
		return
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		app.record(nil, fmt.Errorf("ServiceAccount CA-certificaat is ongeldig"))
		return
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes, err := readNodes(ctx, client, "https://kubernetes.default.svc", credentials+"token")
	app.record(nodes, err)
	if err != nil {
		log.Printf("Nodecontrole mislukt: %v", err)
	}
}

func (app *application) snapshot() (report, int64) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	r := app.result
	if r.CheckedAt != 0 && time.Now().Unix()-r.CheckedAt > 120 {
		r.Status, r.Error, r.Nodes = "unknown", "Nodecontrole is ouder dan 120 seconden", []nodeResult{}
	}
	return r, app.lastSuccess
}

func (app *application) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		app.writeReport(w)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		nodes, nodeLast := app.snapshot()
		ops, opLast := app.operators.snapshot()
		pdbs, pdbLast := app.pdbs.snapshot()
		apis, apiLast := app.apis.snapshot()
		nodeSuccess := nodes.Status == "ok" || nodes.Status == "blocker"
		flag := func(value bool) int {
			if value {
				return 1
			}
			return 0
		}
		fmt.Fprintln(w, "# TYPE upgrade_readiness_checker_info gauge")
		fmt.Fprintln(w, `upgrade_readiness_checker_info{version="0.5.0"} 1`)
		fmt.Fprintln(w, "# TYPE upgrade_readiness_check_success gauge")
		fmt.Fprintf(w, "upgrade_readiness_check_success{check=%q} %d\n", "nodes", flag(nodeSuccess))
		fmt.Fprintf(w, "upgrade_readiness_check_success{check=%q} %d\n", "operators", flag(ops.Success))
		fmt.Fprintf(w, "upgrade_readiness_check_success{check=%q} %d\n", "pdbs", flag(pdbs.Success))
		fmt.Fprintf(w, "upgrade_readiness_check_success{check=%q} %d\n", "apis", flag(apis.Success))
		fmt.Fprintln(w, "# TYPE upgrade_readiness_last_success_timestamp_seconds gauge")
		fmt.Fprintf(w, "upgrade_readiness_last_success_timestamp_seconds{check=%q} %d\n", "nodes", nodeLast)
		fmt.Fprintf(w, "upgrade_readiness_last_success_timestamp_seconds{check=%q} %d\n", "operators", opLast)
		fmt.Fprintf(w, "upgrade_readiness_last_success_timestamp_seconds{check=%q} %d\n", "pdbs", pdbLast)
		fmt.Fprintf(w, "upgrade_readiness_last_success_timestamp_seconds{check=%q} %d\n", "apis", apiLast)
		failures := 0
		if nodeSuccess {
			for _, node := range nodes.Nodes {
				if node.Ready != "True" {
					failures++
				}
			}
		}
		if nodeSuccess || ops.Success || pdbs.Success || apis.Success {
			fmt.Fprintln(w, "# TYPE upgrade_readiness_findings gauge")
			if nodeSuccess {
				fmt.Fprintf(w, "upgrade_readiness_findings{check=%q,severity=%q} %d\n", "nodes", "blocker", failures)
			}
			if ops.Success {
				for _, severity := range []string{"blocker", "warning", "unknown"} {
					count := 0
					for _, f := range ops.Findings {
						if f.Severity == severity {
							count++
						}
					}
					fmt.Fprintf(w, "upgrade_readiness_findings{check=%q,severity=%q} %d\n", "operators", severity, count)
				}
			}
		}
		if pdbs.Success {
			for _, severity := range []string{"blocker", "warning", "unknown"} {
				count := 0
				for _, f := range pdbs.Findings {
					if f.Severity == severity {
						count++
					}
				}
				fmt.Fprintf(w, "upgrade_readiness_findings{check=%q,severity=%q} %d\n", "pdbs", severity, count)
			}
		}
		if apis.Success {
			for _, severity := range []string{"blocker", "warning", "unknown"} {
				count := 0
				for _, f := range apis.Findings {
					if f.Severity == severity {
						count++
					}
				}
				fmt.Fprintf(w, "upgrade_readiness_findings{check=%q,severity=%q} %d\n", "apis", severity, count)
			}
		}
		fmt.Fprintln(w, "# TYPE upgrade_readiness_assessment_complete gauge")
		fmt.Fprintf(w, "upgrade_readiness_assessment_complete{check=%q} %d\n", "operators", flag(ops.Success && ops.Complete))
		fmt.Fprintf(w, "upgrade_readiness_assessment_complete{check=%q} %d\n", "pdbs", flag(pdbs.Success && pdbs.Complete))
		fmt.Fprintf(w, "upgrade_readiness_assessment_complete{check=%q} %d\n", "apis", flag(apis.Success && apis.Complete))
		operatorMetrics(w, ops)
		pdbMetrics(w, pdbs)
		apiMetrics(w, apis)
		if !nodeSuccess {
			return
		}
		fmt.Fprintln(w, "# TYPE upgrade_readiness_node_ready gauge")
		for _, node := range nodes.Nodes {
			fmt.Fprintf(w, "upgrade_readiness_node_ready{node=%q} %d\n", node.Name, flag(node.Ready == "True"))
		}
		fmt.Fprintln(w, "# TYPE upgrade_readiness_nodes_total gauge")
		fmt.Fprintf(w, "upgrade_readiness_nodes_total %d\n", len(nodes.Nodes))
	})
	return mux
}

func main() {
	app := &application{result: report{Status: "unknown", Error: "Eerste nodecontrole is nog niet afgerond", Nodes: []nodeResult{}}}
	go app.operators.run()
	go app.pdbs.run()
	go app.apis.run()
	go func() {
		for {
			app.scan()
			time.Sleep(60 * time.Second)
		}
	}()
	server := &http.Server{Addr: ":8080", Handler: app.handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Println("Readiness checker 0.5.0 listening on port 8080")
	log.Fatal(server.ListenAndServe())
}
