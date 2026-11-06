package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type resourceMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Generation        int64             `json:"generation"`
	Labels            map[string]string `json:"labels"`
	DeletionTimestamp *string           `json:"deletionTimestamp"`
	Annotations       map[string]string `json:"annotations"`
	OwnerReferences   []struct {
		Kind string `json:"kind"`
	} `json:"ownerReferences"`
}
type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}
type pdbObject struct {
	Metadata resourceMeta `json:"metadata"`
	Spec     struct {
		Selector *labelSelector `json:"selector"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration *int64      `json:"observedGeneration"`
		DisruptionsAllowed *int        `json:"disruptionsAllowed"`
		CurrentHealthy     *int        `json:"currentHealthy"`
		DesiredHealthy     *int        `json:"desiredHealthy"`
		ExpectedPods       *int        `json:"expectedPods"`
		Conditions         []condition `json:"conditions"`
	} `json:"status"`
}
type podObject struct {
	Metadata resourceMeta `json:"metadata"`
	Status   struct {
		Phase      string      `json:"phase"`
		Conditions []condition `json:"conditions"`
	} `json:"status"`
}
type pdbResult struct {
	Name               string `json:"name"`
	Namespace          string `json:"namespace"`
	MatchedPods        int    `json:"matched_pods"`
	DrainableReadyPods int    `json:"drainable_ready_pods"`
	StatusCurrent      bool   `json:"status_current"`
	DisruptionsAllowed *int   `json:"disruptions_allowed,omitempty"`
	CurrentHealthy     *int   `json:"current_healthy,omitempty"`
	DesiredHealthy     *int   `json:"desired_healthy,omitempty"`
	ExpectedPods       *int   `json:"expected_pods,omitempty"`
}
type pdbReport struct {
	Status    string      `json:"status"`
	Success   bool        `json:"collection_succeeded"`
	Complete  bool        `json:"assessment_complete"`
	CheckedAt int64       `json:"checked_at_unix"`
	Scope     string      `json:"scope"`
	Error     string      `json:"error,omitempty"`
	PDBs      []pdbResult `json:"pdbs"`
	Findings  []finding   `json:"findings"`
}
type pdbState struct {
	mu          sync.RWMutex
	result      pdbReport
	lastSuccess int64
}

const pdbScope = "Huidige PDB-status, selectors en overlap in alle namespaces; geen drain-simulatie of garantie voor een volledige upgrade"

func (s *labelSelector) valid() bool {
	if s == nil {
		return true
	}
	for _, e := range s.MatchExpressions {
		if e.Key == "" {
			return false
		}
		switch e.Operator {
		case "In", "NotIn":
			if len(e.Values) == 0 {
				return false
			}
		case "Exists", "DoesNotExist":
			if len(e.Values) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (s *labelSelector) matches(labels map[string]string) bool {
	if s == nil {
		return false
	} // policy/v1: null selects none; {} selects all in namespace.
	for k, v := range s.MatchLabels {
		actual, present := labels[k]
		if !present || actual != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		actual, present := labels[e.Key]
		member := false
		for _, v := range e.Values {
			if actual == v {
				member = true
			}
		}
		switch e.Operator {
		case "In":
			if !present || !member {
				return false
			}
		case "NotIn":
			if present && member {
				return false
			}
		case "Exists":
			if !present {
				return false
			}
		case "DoesNotExist":
			if present {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func activePod(p podObject) bool {
	return p.Metadata.DeletionTimestamp == nil && p.Status.Phase != "Succeeded" && p.Status.Phase != "Failed"
}
func drainableReady(p podObject) bool {
	if !activePod(p) || p.Status.Phase != "Running" {
		return false
	}
	if _, mirror := p.Metadata.Annotations["kubernetes.io/config.mirror"]; mirror {
		return false
	}
	for _, owner := range p.Metadata.OwnerReferences {
		if owner.Kind == "DaemonSet" {
			return false
		}
	}
	c, _ := findCondition(p.Status.Conditions, "Ready")
	return c.Status == "True"
}
func assessPDBs(objects []pdbObject, pods []podObject) pdbReport {
	r := pdbReport{Status: "ok", Success: true, Complete: true, Scope: pdbScope, PDBs: []pdbResult{}, Findings: []finding{}}
	add := func(resource, severity, reason, message, advice string) {
		r.Findings = append(r.Findings, finding{resource, severity, "PDB", reason, message, advice})
	}
	coverage := map[string][]string{}
	for _, pdb := range objects {
		resource := "PodDisruptionBudget/" + pdb.Metadata.Namespace + "/" + pdb.Metadata.Name
		result := pdbResult{Name: pdb.Metadata.Name, Namespace: pdb.Metadata.Namespace}
		if !pdb.Spec.Selector.valid() {
			add(resource, "unknown", "InvalidSelector", "Selector kan niet betrouwbaar worden beoordeeld.", "Controleer de matchExpressions en labelselector.")
			r.PDBs = append(r.PDBs, result)
			continue
		}
		for _, pod := range pods {
			if pod.Metadata.Namespace != pdb.Metadata.Namespace || !activePod(pod) || !pdb.Spec.Selector.matches(pod.Metadata.Labels) {
				continue
			}
			result.MatchedPods++
			key := pod.Metadata.Namespace + "/" + pod.Metadata.Name
			coverage[key] = append(coverage[key], resource)
			if drainableReady(pod) {
				result.DrainableReadyPods++
			}
		}
		st := pdb.Status
		current := pdb.Metadata.Generation > 0 && st.ObservedGeneration != nil && *st.ObservedGeneration == pdb.Metadata.Generation && st.DisruptionsAllowed != nil && st.CurrentHealthy != nil && st.DesiredHealthy != nil && st.ExpectedPods != nil
		if current {
			current = *st.DisruptionsAllowed >= 0 && *st.CurrentHealthy >= 0 && *st.DesiredHealthy >= 0 && *st.ExpectedPods >= 0
		}
		for _, c := range st.Conditions {
			if c.Reason == "SyncFailed" {
				current = false
			}
		}
		result.StatusCurrent = current
		if !current {
			add(resource, "unknown", "StatusNotCurrent", "PDB-status ontbreekt, is verouderd of de disruption controller meldt SyncFailed.", "Wacht op de disruption controller; controleer observedGeneration, PDB-condities en events als dit blijft aanhouden.")
		} else {
			result.DisruptionsAllowed = st.DisruptionsAllowed
			result.CurrentHealthy = st.CurrentHealthy
			result.DesiredHealthy = st.DesiredHealthy
			result.ExpectedPods = st.ExpectedPods
			if *st.DisruptionsAllowed == 0 && result.DrainableReadyPods > 0 {
				add(resource, "blocker", "NoDisruptionsAllowed", "Er mag momenteel geen gezonde pod worden uitgezet, terwijl er gezonde pods onder dit PDB vallen die bij een drain worden verwijderd.", "Controleer minAvailable/maxUnavailable en herstel ongezonde replicas of schaal waar mogelijk op. Stem aanpassingen af op de beschikbaarheidseisen; verwijder het PDB niet zomaar. Dit is een huidige drainbeperking, geen bewezen configuratiefout.")
			}
		}
		if result.MatchedPods == 0 {
			add(resource, "warning", "NoMatchingPods", "De selector vindt momenteel geen actieve pods in deze namespace.", "Controleer labels en namespace. Een naar nul geschaalde workload kan bewust geen pods hebben; ontbrekende pods bewijzen geen fout.")
		}
		if pdb.Spec.Selector != nil && len(pdb.Spec.Selector.MatchLabels) == 0 && len(pdb.Spec.Selector.MatchExpressions) == 0 {
			add(resource, "warning", "NamespaceWideSelector", "Een lege policy/v1-selector selecteert alle pods in de namespace.", "Controleer of bescherming van alle pods in deze namespace de bedoeling is; gebruik anders een gerichte labelselector.")
		}
		r.PDBs = append(r.PDBs, result)
	}
	// Stable pod order comes from the API list, not map iteration.
	for _, pod := range pods {
		key := pod.Metadata.Namespace + "/" + pod.Metadata.Name
		if len(coverage[key]) > 1 {
			add("Pod/"+key, "blocker", "OverlappingPDBs", "Deze actieve pod valt onder meerdere PDBs: "+strings.Join(coverage[key], ", "), "Maak selectors zo specifiek dat een pod door hoogstens één PDB wordt geselecteerd. Overlap kan eviction blokkeren.")
		}
	}
	for _, f := range r.Findings {
		if f.Severity == "unknown" {
			r.Complete = false
		}
	}
	r.Status = combinedStatus(r.Findings)
	return r
}

func readList[T any](ctx context.Context, client *http.Client, base, path, tokenPath string) ([]T, error) {
	result := []T{}
	continuation := ""
	seen := map[string]bool{}
	for {
		q := url.Values{"limit": {"500"}}
		if continuation != "" {
			q.Set("continue", continuation)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := apiJSON(ctx, client, base+path+"?"+q.Encode(), tokenPath, &page); err != nil {
			return nil, fmt.Errorf("uitlezen %s: %w", path, err)
		}
		if page.Items == nil {
			return nil, fmt.Errorf("API-lijst %s bevat geen items-veld", path)
		}
		result = append(result, page.Items...)
		continuation = page.Metadata.Continue
		if continuation == "" {
			return result, nil
		}
		if seen[continuation] {
			return nil, fmt.Errorf("herhaalde pagineringstoken voor %s", path)
		}
		seen[continuation] = true
	}
}
func readPDBs(ctx context.Context, client *http.Client, base, tokenPath string) (pdbReport, error) {
	objects, err := readList[pdbObject](ctx, client, base, "/apis/policy/v1/poddisruptionbudgets", tokenPath)
	if err != nil {
		return pdbReport{}, err
	}
	pods, err := readList[podObject](ctx, client, base, "/api/v1/pods", tokenPath)
	if err != nil {
		return pdbReport{}, err
	}
	for _, p := range objects {
		if p.Metadata.Name == "" || p.Metadata.Namespace == "" {
			return pdbReport{}, fmt.Errorf("PDB zonder naam of namespace ontvangen")
		}
	}
	for _, p := range pods {
		if p.Metadata.Name == "" || p.Metadata.Namespace == "" {
			return pdbReport{}, fmt.Errorf("pod zonder naam of namespace ontvangen")
		}
	}
	return assessPDBs(objects, pods), nil
}
func (s *pdbState) record(r pdbReport, err error) {
	if err != nil {
		r = pdbReport{Status: "error", Error: err.Error(), Scope: pdbScope, PDBs: []pdbResult{}, Findings: []finding{}}
	}
	r.CheckedAt = time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = r
	if r.Success {
		s.lastSuccess = r.CheckedAt
	}
}
func (s *pdbState) snapshot() (pdbReport, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.result
	if r.Status == "" {
		r.Status = "unknown"
		r.Error = "Eerste PDB-controle is nog niet afgerond"
	}
	if r.CheckedAt != 0 && time.Now().Unix()-r.CheckedAt > 120 {
		r = pdbReport{Status: "unknown", CheckedAt: r.CheckedAt, Error: "PDB-controle is ouder dan 120 seconden", Scope: pdbScope, PDBs: []pdbResult{}, Findings: []finding{}}
	}
	return r, s.lastSuccess
}
func (s *pdbState) scan() {
	ca, err := os.ReadFile(credentials + "ca.crt")
	if err != nil {
		s.record(pdbReport{}, fmt.Errorf("ServiceAccount CA-certificaat niet leesbaar"))
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		s.record(pdbReport{}, fmt.Errorf("ongeldig ServiceAccount CA-certificaat"))
		return
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := readPDBs(ctx, client, "https://kubernetes.default.svc", credentials+"token")
	s.record(r, err)
}
func (s *pdbState) run() {
	for {
		s.scan()
		time.Sleep(60 * time.Second)
	}
}
func pdbMetrics(w http.ResponseWriter, r pdbReport) {
	if !r.Success {
		return
	}
	fmt.Fprintf(w, "# TYPE upgrade_readiness_pdbs_total gauge\nupgrade_readiness_pdbs_total %d\n", len(r.PDBs))
	for _, metric := range []string{"disruptions_allowed", "matched_pods", "status_current"} {
		fmt.Fprintf(w, "# TYPE upgrade_readiness_pdb_%s gauge\n", metric)
		for _, p := range r.PDBs {
			value := p.MatchedPods
			if metric == "status_current" {
				value = 0
				if p.StatusCurrent {
					value = 1
				}
			}
			if metric == "disruptions_allowed" {
				if p.DisruptionsAllowed == nil {
					continue
				}
				value = *p.DisruptionsAllowed
			}
			fmt.Fprintf(w, "upgrade_readiness_pdb_%s{namespace=%q,pdb=%q} %d\n", metric, p.Namespace, p.Name, value)
		}
	}
}
