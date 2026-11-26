package adguard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// newFakeAdGuard starts a server that mimics the AdGuard Home >= v1.0 HTTP
// API: removed endpoints such as GET /control/clients/find answer 404, like
// the real server does.
func newFakeAdGuard(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/control/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"running":true,"protection_enabled":true,"version":"v1.0.1"}`))
	})
	mux.HandleFunc("/control/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"num_dns_queries":42,"top_clients":[{"10.0.0.1":30},{"10.0.0.2":12}]}`))
	})
	mux.HandleFunc("/control/querylog", func(w http.ResponseWriter, r *http.Request) {
		// response_status was removed from the API in v1.0.0.
		if r.URL.Query().Has("response_status") {
			t.Errorf("querylog called with removed parameter response_status: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"data":[]}`))
	})
	mux.HandleFunc("/control/clients/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Clients []struct {
				ID string `json:"id"`
			} `json:"clients"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		names := map[string]string{"10.0.0.1": "laptop"}
		resp := []map[string]map[string]string{}
		for _, c := range req.Clients {
			// Unknown clients come back with an empty name.
			resp = append(resp, map[string]map[string]string{c.ID: {"name": names[c.ID]}})
		}
		json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGetStatisticsAgainstAdGuardV1(t *testing.T) {
	srv := newFakeAdGuard(t)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient("http", u.Hostname(), "", "", u.Port(), time.Second, "1000", true, false)
	all := c.getStatistics()

	if !all.status.Running {
		t.Errorf("status not parsed: %+v", all.status)
	}
	if all.stats.DnsQueries != 42 {
		t.Errorf("stats not parsed: %+v", all.stats)
	}
	if got := all.rdns["10.0.0.1"]; got != "laptop" {
		t.Errorf("rdns[10.0.0.1] = %q, want %q", got, "laptop")
	}
	// A client without a name must fall back to its IP, so it is left out.
	if got, ok := all.rdns["10.0.0.2"]; ok {
		t.Errorf("rdns[10.0.0.2] = %q, want no entry", got)
	}
}
