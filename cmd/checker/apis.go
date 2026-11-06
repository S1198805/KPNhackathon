package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIRequestCount totals are rolling windows, not monotonically increasing counters.
// currentHour also appears in last24h: never add them to status.requestCount.
type apiUser struct {
	Username     string `json:"username"`
	RequestCount int64  `json:"requestCount"`
}
type apiHour struct {
	RequestCount *int64 `json:"requestCount"`
	ByNode       []struct {
		ByUser []apiUser `json:"byUser"`
	} `json:"byNode"`
}
type apiRequestObject struct {
	Metadata resourceMeta `json:"metadata"`
	Status   struct {
		RemovedInRelease string    `json:"removedInRelease"`
		RequestCount     *int64    `json:"requestCount"`
		CurrentHour      apiHour   `json:"currentHour"`
		Last24h          []apiHour `json:"last24h"`
	} `json:"status"`
}
type deprecatedAPIResult struct {
	Name                string   `json:"name"`
	RemovedInRelease    string   `json:"removed_in_kubernetes"`
	RequestsLast24h     *int64   `json:"requests_last_24h,omitempty"`
	RequestsCurrentHour *int64   `json:"requests_current_hour,omitempty"`
	Active              bool     `json:"observed_requests"`
	TargetAffected      bool     `json:"target_affected"`
	Attribution         string   `json:"attribution"`
	Clients             []string `json:"sampled_clients"`
	IgnoredClients      []string `json:"sampled_system_scanners"`
}
type apiReport struct {
	Status           string                `json:"status"`
	Success          bool                  `json:"collection_succeeded"`
	Complete         bool                  `json:"assessment_complete"`
	CheckedAt        int64                 `json:"checked_at_unix"`
	TargetKubernetes string                `json:"target_kubernetes,omitempty"`
	TargetConfigured bool                  `json:"target_configured"`
	Scope            string                `json:"scope"`
	Error            string                `json:"error,omitempty"`
	ResourcesScanned int                   `json:"api_requestcounts_scanned"`
	APIs             []deprecatedAPIResult `json:"deprecated_apis"`
	Findings         []finding             `json:"findings"`
}
type apiState struct {
	mu          sync.RWMutex
	result      apiReport
	lastSuccess int64
}

const apiScope = "APIRequestCount: waargenomen API-gebruik in het beschikbare venster tot 24 uur; geen volledige Git-, resource- of supportscan. Clients zijn steekproeven; stilstaande workloads en externe tools kunnen ontbreken. Verwijderversies zijn Kubernetes-versies."

var kubeReleasePattern = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)$`)

func kubeMinor(value string) (int, bool) {
	if !kubeReleasePattern.MatchString(value) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(value, "1."))
	return n, err == nil
}
func ignoredAPIUser(name string) bool {
	switch name {
	case "system:serviceaccount:kube-system:generic-garbage-collector", "system:serviceaccount:kube-system:namespace-controller", "system:kube-controller-manager", "system:cluster-policy-controller":
		return true
	}
	return false
}
func sampledAPIClients(p apiRequestObject) ([]string, []string) {
	clients, ignored := map[string]bool{}, map[string]bool{}
	hours := append([]apiHour{p.Status.CurrentHour}, p.Status.Last24h...)
	for _, hour := range hours {
		for _, node := range hour.ByNode {
			for _, u := range node.ByUser {
				if u.RequestCount <= 0 || u.Username == "" {
					continue
				}
				if ignoredAPIUser(u.Username) {
					ignored[u.Username] = true
				} else {
					clients[u.Username] = true
				}
			}
		}
	}
	list := func(m map[string]bool) []string {
		result := []string{}
		for k := range m {
			result = append(result, k)
		}
		sort.Strings(result)
		return result
	}
	return list(clients), list(ignored)
}
func assessAPIs(objects []apiRequestObject, target string) apiReport {
	target = strings.TrimSpace(target)
	minor, configured := kubeMinor(target)
	r := apiReport{Status: "ok", Success: true, Complete: true, TargetKubernetes: target, TargetConfigured: configured, Scope: apiScope, ResourcesScanned: len(objects), APIs: []deprecatedAPIResult{}, Findings: []finding{}}
	add := func(resource, severity, reason, message, advice string) {
		r.Findings = append(r.Findings, finding{resource, severity, "DeprecatedAPI", reason, message, advice})
	}
	if !configured {
		add("Checker/target", "unknown", "TargetKubernetesNotConfigured", "Een geldige Kubernetes-doelversie ontbreekt; API-inventarisatie werkt, maar de vergelijking met een upgrade is onvolledig.", "Stel TARGET_KUBERNETES_VERSION in op de Kubernetes minorversie van de beoogde OpenShift-release (formaat 1.xx). Vul geen OpenShift-versie 4.xx in. Kies de doelrelease met de beheerder; CRC zelf heeft geen ondersteund upgradepad.")
	}
	if len(objects) == 0 {
		add("APIRequestCount/inventory", "unknown", "NoObservationData", "Er zijn geen APIRequestCounts ontvangen; dekking kan niet worden vastgesteld.", "Controleer de APIRequestCount-controller en laat normale workloads draaien. Een lege historie is geen bewijs dat alle API-clients compatibel zijn.")
	}
	for _, object := range objects {
		resource := "APIRequestCount/" + object.Metadata.Name
		st := object.Status
		if st.RequestCount == nil || *st.RequestCount < 0 || (st.CurrentHour.RequestCount != nil && *st.CurrentHour.RequestCount < 0) {
			add(resource, "unknown", "InvalidRequestStatus", "API-aanroeptellingen ontbreken of zijn ongeldig.", "Controleer de status en events van dit APIRequestCount; wacht op de controller.")
			continue
		}
		if st.RemovedInRelease == "" {
			continue
		}
		removed, valid := kubeMinor(st.RemovedInRelease)
		result := deprecatedAPIResult{Name: object.Metadata.Name, RemovedInRelease: st.RemovedInRelease, RequestsLast24h: st.RequestCount, RequestsCurrentHour: st.CurrentHour.RequestCount, Clients: []string{}, IgnoredClients: []string{}}
		result.Active = *st.RequestCount > 0 || (st.CurrentHour.RequestCount != nil && *st.CurrentHour.RequestCount > 0)
		result.TargetAffected = configured && valid && removed <= minor
		result.Clients, result.IgnoredClients = sampledAPIClients(object)
		result.Attribution = "no_observed_requests"
		if result.Active {
			result.Attribution = "unattributed"
			if len(result.Clients) > 0 {
				result.Attribution = "client_observed"
			} else if len(result.IgnoredClients) > 0 {
				result.Attribution = "system_scanners_only_in_samples"
			}
		}
		r.APIs = append(r.APIs, result)
		if !valid {
			add(resource, "unknown", "InvalidRemovalVersion", "De gemelde verwijderversie heeft geen herkenbaar Kubernetes minorformaat.", "Controleer status.removedInRelease en de officiële migratiedocumentatie.")
			continue
		}
		if !result.Active {
			continue
		}
		severity, reason := "warning", "DeprecatedAPIObserved"
		message := "Aanroepen waargenomen voor een API die volgens het cluster verdwijnt in Kubernetes " + st.RemovedInRelease + "."
		advice := "Onderzoek de getoonde clients en migreer de betreffende applicatie, controller of automatisering naar een ondersteunde API-versie volgens de migratiehandleiding. Controleer ook Git-manifests en externe tools; verwijder niet zomaar resources."
		if result.Attribution == "client_observed" && result.TargetAffected {
			severity, reason = "blocker", "RemovedAPIClientObserved"
			message += " Een niet-uitgezonderde client is waargenomen en de verwijderversie ligt op of vóór de ingestelde doelversie. Dit is een preflightbevinding; geen rechtstreeks door CVO gemelde upgradeblokkade."
		} else if result.Attribution == "system_scanners_only_in_samples" {
			reason = "SystemScannerRequestsObserved"
			message += " De beschikbare gebruikerssteekproeven tonen alleen ingebouwde systeemscanners die Red Hat uitzondert; dit bewijst geen applicatieafhankelijkheid."
			advice = "Deze systeemgebruikers vereisen op zichzelf geen migratie. Controleer bij twijfel de volledige clientinventaris; de topgebruikers zijn slechts een steekproef."
		} else if result.Attribution == "unattributed" {
			reason = "DeprecatedAPIClientUnknown"
			message += " Er is geen bruikbare clientsteekproef; applicatiegebruik en systeemscans zijn niet te onderscheiden."
			add(resource, "unknown", "ClientAttributionIncomplete", "De bron van het waargenomen verouderde API-gebruik is onbekend.", "Onderzoek de APIRequestCount-gebruikersdetails en zo nodig bestaande auditlogs voordat je dit als upgradeblokkade beoordeelt.")
		}
		add(resource, severity, reason, message, advice)
	}
	for _, f := range r.Findings {
		if f.Severity == "unknown" {
			r.Complete = false
		}
	}
	r.Status = combinedStatus(r.Findings)
	return r
}
func readAPIs(ctx context.Context, client *http.Client, base, tokenPath, target string) (apiReport, error) {
	objects, err := readList[apiRequestObject](ctx, client, base, "/apis/apiserver.openshift.io/v1/apirequestcounts", tokenPath)
	if err != nil {
		return apiReport{}, err
	}
	for _, p := range objects {
		if p.Metadata.Name == "" {
			return apiReport{}, fmt.Errorf("APIRequestCount zonder naam ontvangen")
		}
	}
	return assessAPIs(objects, target), nil
}
func (s *apiState) record(r apiReport, err error) {
	if err != nil {
		r = apiReport{Status: "error", Error: err.Error(), Scope: apiScope, APIs: []deprecatedAPIResult{}, Findings: []finding{}}
	}
	r.CheckedAt = time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = r
	if r.Success {
		s.lastSuccess = r.CheckedAt
	}
}
func (s *apiState) snapshot() (apiReport, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.result
	if r.Status == "" {
		r.Status = "unknown"
		r.Scope = apiScope
		r.Error = "Eerste API-controle is nog niet afgerond"
	}
	if r.CheckedAt != 0 && time.Now().Unix()-r.CheckedAt > 120 {
		r = apiReport{Status: "unknown", CheckedAt: r.CheckedAt, Scope: apiScope, Error: "API-controle is ouder dan 120 seconden", APIs: []deprecatedAPIResult{}, Findings: []finding{}}
	}
	return r, s.lastSuccess
}
func (s *apiState) scan() {
	ca, err := os.ReadFile(credentials + "ca.crt")
	if err != nil {
		s.record(apiReport{}, fmt.Errorf("ServiceAccount CA-certificaat niet leesbaar"))
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		s.record(apiReport{}, fmt.Errorf("ongeldig ServiceAccount CA-certificaat"))
		return
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := readAPIs(ctx, client, "https://kubernetes.default.svc", credentials+"token", os.Getenv("TARGET_KUBERNETES_VERSION"))
	s.record(r, err)
}
func (s *apiState) run() {
	for {
		s.scan()
		time.Sleep(60 * time.Second)
	}
}
func apiMetrics(w http.ResponseWriter, r apiReport) {
	if !r.Success {
		return
	}
	configured := 0
	if r.TargetConfigured {
		configured = 1
	}
	fmt.Fprintf(w, "# TYPE upgrade_readiness_api_target_configured gauge\nupgrade_readiness_api_target_configured %d\n", configured)
	fmt.Fprintf(w, "# TYPE upgrade_readiness_api_requestcounts_total gauge\nupgrade_readiness_api_requestcounts_total %d\n", r.ResourcesScanned)
	fmt.Fprintf(w, "# TYPE upgrade_readiness_deprecated_apis_total gauge\nupgrade_readiness_deprecated_apis_total %d\n", len(r.APIs))
	if r.TargetConfigured {
		fmt.Fprintf(w, "# TYPE upgrade_readiness_api_target_info gauge\nupgrade_readiness_api_target_info{kubernetes=%q} 1\n", r.TargetKubernetes)
	}
	// Gauges: the server rolls the window and can reset counts on restart.
	for _, window := range []string{"24h", "current_hour"} {
		fmt.Fprintf(w, "# TYPE upgrade_readiness_deprecated_api_requests_%s gauge\n", window)
		for _, p := range r.APIs {
			value := p.RequestsLast24h
			if window == "current_hour" {
				value = p.RequestsCurrentHour
			}
			if value == nil {
				continue
			}
			fmt.Fprintf(w, "upgrade_readiness_deprecated_api_requests_%s{api=%q,removed_in=%q} %d\n", window, p.Name, p.RemovedInRelease, *value)
		}
	}
	fmt.Fprintln(w, "# TYPE upgrade_readiness_deprecated_api_target_affected gauge")
	if r.TargetConfigured {
		for _, p := range r.APIs {
			if _, ok := kubeMinor(p.RemovedInRelease); !ok {
				continue
			}
			value := 0
			if p.TargetAffected {
				value = 1
			}
			fmt.Fprintf(w, "upgrade_readiness_deprecated_api_target_affected{api=%q,removed_in=%q} %d\n", p.Name, p.RemovedInRelease, value)
		}
	}
}
