package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type condition struct{ Type, Status, Reason, Message string }
type operatorObject struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Status struct {
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}
type operatorResult struct {
	Name        string `json:"name"`
	Available   string `json:"available"`
	Degraded    string `json:"degraded"`
	Progressing string `json:"progressing"`
	Upgradeable string `json:"upgradeable"`
}
type finding struct {
	Resource  string `json:"resource"`
	Severity  string `json:"severity"`
	Condition string `json:"condition"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
	Advice    string `json:"advice"`
}
type operatorReport struct {
	Status             string           `json:"status"`
	Success            bool             `json:"collection_succeeded"`
	Complete           bool             `json:"assessment_complete"`
	CheckedAt          int64            `json:"checked_at_unix"`
	Scope              string           `json:"scope"`
	ClusterVersion     string           `json:"cluster_version,omitempty"`
	ClusterUpgradeable string           `json:"cluster_upgradeable,omitempty"`
	Error              string           `json:"error,omitempty"`
	Operators          []operatorResult `json:"operators"`
	Findings           []finding        `json:"findings"`
}
type operatorState struct {
	mu          sync.RWMutex
	result      operatorReport
	lastSuccess int64
}

func findCondition(conditions []condition, kind string) (condition, bool) {
	for _, c := range conditions {
		if c.Type == kind {
			if c.Status != "True" && c.Status != "False" {
				c.Status = "Unknown"
			}
			return c, true
		}
	}
	return condition{Type: kind, Status: "Unknown"}, false
}

func assessOperators(operators []operatorObject, version string, clusterConditions []condition) operatorReport {
	r := operatorReport{Status: "ok", Success: true, Complete: true, Scope: "minor-upgrade-preflight; ClusterOperators only", ClusterVersion: version, Operators: []operatorResult{}, Findings: []finding{}}
	add := func(resource, severity string, c condition, advice string) {
		r.Findings = append(r.Findings, finding{resource, severity, c.Type, c.Reason, c.Message, advice})
	}
	for _, op := range operators {
		available, _ := findCondition(op.Status.Conditions, "Available")
		degraded, _ := findCondition(op.Status.Conditions, "Degraded")
		progressing, _ := findCondition(op.Status.Conditions, "Progressing")
		upgradeable, present := findCondition(op.Status.Conditions, "Upgradeable")
		if !present {
			upgradeable.Status = "NotReported"
		}
		r.Operators = append(r.Operators, operatorResult{op.Metadata.Name, available.Status, degraded.Status, progressing.Status, upgradeable.Status})
		resource := "ClusterOperator/" + op.Metadata.Name
		for _, c := range []condition{available, degraded} {
			bad := (c.Type == "Available" && c.Status == "False") || (c.Type == "Degraded" && c.Status == "True")
			if bad {
				add(resource, "blocker", c, "Onderzoek de reason en message, Operator-events en betrokken pods. Herstel het platformonderdeel voordat je een upgrade plant.")
			}
			if c.Status == "Unknown" {
				add(resource, "unknown", c, "Een vereiste Operatorconditie ontbreekt of is onbekend. Onderzoek de Operator; beschouw deze controle niet als groen.")
			}
		}
		if progressing.Status == "True" {
			add(resource, "warning", progressing, "De Operator voert een wijziging uit. Wacht tot deze klaar is; onderzoek events als dit blijft aanhouden.")
		}
		if upgradeable.Status == "False" {
			add(resource, "blocker", upgradeable, "Deze Operator blokkeert een minorupgrade. Volg de reason en message. Dit betekent niet automatisch dat een patchupdate geblokkeerd is.")
		}
		if present && upgradeable.Status == "Unknown" {
			add(resource, "unknown", upgradeable, "De upgradegeschiktheid is onbekend. Controleer de Operator en de documentatie voor de beoogde versie.")
		}
	}
	c, present := findCondition(clusterConditions, "Upgradeable")
	r.ClusterUpgradeable = c.Status
	if !present {
		r.ClusterUpgradeable = "NotReported"
	}
	if present && c.Status == "False" {
		add("ClusterVersion/version", "blocker", c, "Het cluster meldt een blokkade voor minorupgrades. Lees de reason en message. CRC heeft geen ondersteund upgradepad; pas standaard CRC-instellingen niet blind aan.")
	}
	if present && c.Status == "Unknown" {
		add("ClusterVersion/version", "unknown", c, "De upgradegeschiktheid van het cluster is onbekend. Onderzoek de clusterversieconditie en de beoogde update.")
	}
	for _, f := range r.Findings {
		if f.Severity == "unknown" {
			r.Complete = false
		}
	}
	r.Status = combinedStatus(r.Findings)
	return r
}
func combinedStatus(findings []finding) string {
	for _, severity := range []string{"blocker", "unknown", "warning"} {
		for _, f := range findings {
			if f.Severity == severity {
				return severity
			}
		}
	}
	return "ok"
}

func apiJSON(ctx context.Context, client *http.Client, address, tokenPath string, out any) error {
	token, err := os.ReadFile(tokenPath)
	if err != nil || strings.TrimSpace(string(token)) == "" {
		return fmt.Errorf("ServiceAccount-token ontbreekt of is niet leesbaar")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("OpenShift API niet bereikbaar: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("OpenShift API geeft HTTP %d; controleer bij 401/403 de ServiceAccount-leesrechten op de opgevraagde resources", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("ongeldig OpenShift API-antwoord: %w", err)
	}
	return nil
}
func readOperators(ctx context.Context, client *http.Client, base, tokenPath string) (operatorReport, error) {
	objects := []operatorObject{}
	continuation := ""
	for {
		q := url.Values{"limit": {"500"}}
		if continuation != "" {
			q.Set("continue", continuation)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []operatorObject `json:"items"`
		}
		if err := apiJSON(ctx, client, base+"/apis/config.openshift.io/v1/clusteroperators?"+q.Encode(), tokenPath, &page); err != nil {
			return operatorReport{}, err
		}
		for _, op := range page.Items {
			if op.Metadata.Name == "" {
				return operatorReport{}, fmt.Errorf("Operator zonder naam ontvangen")
			}
		}
		objects = append(objects, page.Items...)
		continuation = page.Metadata.Continue
		if continuation == "" {
			break
		}
	}
	if len(objects) == 0 {
		return operatorReport{}, fmt.Errorf("geen ClusterOperators ontvangen; beoordeling is onbekend")
	}
	var version struct {
		Status struct {
			Desired struct {
				Version string `json:"version"`
			} `json:"desired"`
			Conditions []condition `json:"conditions"`
		} `json:"status"`
	}
	if err := apiJSON(ctx, client, base+"/apis/config.openshift.io/v1/clusterversions/version", tokenPath, &version); err != nil {
		return operatorReport{}, err
	}
	if version.Status.Desired.Version == "" {
		return operatorReport{}, fmt.Errorf("huidige OpenShift-versie ontbreekt in ClusterVersion")
	}
	return assessOperators(objects, version.Status.Desired.Version, version.Status.Conditions), nil
}

func (s *operatorState) record(r operatorReport, err error) {
	if err != nil {
		r = operatorReport{Status: "error", Error: err.Error(), Scope: "minor-upgrade-preflight; ClusterOperators only", Operators: []operatorResult{}, Findings: []finding{}}
	}
	r.CheckedAt = time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = r
	if r.Success {
		s.lastSuccess = r.CheckedAt
	}
}
func (s *operatorState) snapshot() (operatorReport, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.result
	if r.Status == "" {
		r.Status = "unknown"
		r.Error = "Eerste Operatorcontrole is nog niet afgerond"
	}
	if r.CheckedAt != 0 && time.Now().Unix()-r.CheckedAt > 120 {
		r.Status = "unknown"
		r.Success = false
		r.Complete = false
		r.Error = "Operatorcontrole is ouder dan 120 seconden"
		r.Operators = nil
		r.Findings = nil
	}
	return r, s.lastSuccess
}
func (s *operatorState) scan() {
	ca, err := os.ReadFile(credentials + "ca.crt")
	if err != nil {
		s.record(operatorReport{}, fmt.Errorf("ServiceAccount CA-certificaat niet leesbaar"))
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		s.record(operatorReport{}, fmt.Errorf("ongeldig ServiceAccount CA-certificaat"))
		return
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := readOperators(ctx, client, "https://kubernetes.default.svc", credentials+"token")
	s.record(r, err)
}
func (s *operatorState) run() {
	for {
		s.scan()
		time.Sleep(60 * time.Second)
	}
}
func operatorMetrics(w http.ResponseWriter, r operatorReport) {
	if !r.Success {
		return
	}
	fmt.Fprintf(w, "# TYPE upgrade_readiness_cluster_version_info gauge\nupgrade_readiness_cluster_version_info{version=%q} 1\n", r.ClusterVersion)
	fmt.Fprintf(w, "# TYPE upgrade_readiness_cluster_upgradeable gauge\nupgrade_readiness_cluster_upgradeable{status=%q} 1\n", r.ClusterUpgradeable)
	fmt.Fprintf(w, "# TYPE upgrade_readiness_operators_total gauge\nupgrade_readiness_operators_total %d\n", len(r.Operators))
	fmt.Fprintln(w, "# TYPE upgrade_readiness_operator_condition gauge")
	for _, op := range r.Operators {
		for _, c := range []struct{ name, status string }{{"Available", op.Available}, {"Degraded", op.Degraded}, {"Progressing", op.Progressing}, {"Upgradeable", op.Upgradeable}} {
			fmt.Fprintf(w, "upgrade_readiness_operator_condition{operator=%q,condition=%q,status=%q} 1\n", op.Name, c.name, c.status)
		}
	}

}
func (app *application) writeReport(w http.ResponseWriter) {
	nodes, _ := app.snapshot()
	operators, _ := app.operators.snapshot()
	pdbs, _ := app.pdbs.snapshot()
	apis, _ := app.apis.snapshot()
	status := "ok"
	if nodes.Status == "error" || nodes.Status == "unknown" || !operators.Success || !operators.Complete || !pdbs.Success || !pdbs.Complete || !apis.Success || !apis.Complete {
		status = "unknown"
	}
	if status == "ok" && (operators.Status == "warning" || pdbs.Status == "warning" || apis.Status == "warning") {
		status = "warning"
	}
	if nodes.Status == "blocker" || operators.Status == "blocker" || pdbs.Status == "blocker" || apis.Status == "blocker" {
		status = "blocker"
	}
	json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
		Scope  string `json:"scope"`
		Checks struct {
			Nodes     report         `json:"nodes"`
			Operators operatorReport `json:"operators"`
			PDBs      pdbReport      `json:"pdbs"`
			APIs      apiReport      `json:"apis"`
		} `json:"checks"`
	}{status, "Node Ready, ClusterOperators, huidige PDB-drainbeperkingen en APIRequestCount-gebruik; unsupported resources buiten verwijderde APIs zijn nog niet beoordeeld", struct {
		Nodes     report         `json:"nodes"`
		Operators operatorReport `json:"operators"`
		PDBs      pdbReport      `json:"pdbs"`
		APIs      apiReport      `json:"apis"`
	}{nodes, operators, pdbs, apis}})
}
